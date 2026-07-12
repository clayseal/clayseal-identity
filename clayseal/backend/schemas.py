"""Pydantic request/response models for the public API."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field

# Upper bound on a single attestation document (a signed JWT of node + workload
# evidence is a few KB at most). This is a per-field guard against a pathological
# payload inflating RSA-verify/parse work; a global request body-size limit still
# belongs at the edge (ALB/API gateway / uvicorn --limit-request-*).
MAX_ATTESTATION_DOCUMENT_CHARS = 16 * 1024
MAX_JWT_CHARS = 16 * 1024
MAX_CAPABILITY_TOKEN_CHARS = 64 * 1024
MAX_PEM_CHARS = 8 * 1024
MAX_SELECTORS_PER_ENTRY = 64
MAX_SCOPES_PER_ENTRY = 256
MAX_CAPABILITIES_PER_ENTRY = 256

ShortText = Annotated[str, Field(min_length=1, max_length=200)]
SelectorText = Annotated[str, Field(min_length=1, max_length=500)]
ScopeText = Annotated[str, Field(min_length=1, max_length=200)]


# --- Customers ------------------------------------------------------------- #
class CustomerCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)


class CustomerOut(BaseModel):
    customer_id: str
    name: str
    api_key: str


class ApiKeyCreate(BaseModel):
    name: ShortText
    scopes: list[
        Literal["admin", "issuer", "verifier", "reader", "revoker"]
    ] = Field(..., min_length=1, max_length=5)


class ApiKeyOut(BaseModel):
    id: str
    name: str
    scopes: list[str]
    status: str
    created_at: datetime
    revoked_at: datetime | None = None

    model_config = {"from_attributes": True}


class ApiKeyCreateOut(ApiKeyOut):
    api_key: str


# --- Node attestors (admin: register trust anchors) ------------------------ #
class NodeAttestorCreate(BaseModel):
    type: str = Field(..., pattern="^(k8s_psat|aws_iid|gcp_iit)$")
    public_pem: str = Field(..., min_length=1, max_length=MAX_PEM_CHARS)
    description: str = Field(default="", max_length=500)


class NodeAttestorOut(BaseModel):
    id: str
    customer_id: str
    type: str
    description: str
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Capabilities ---------------------------------------------------------- #
class Capability(BaseModel):
    """A fine-grained ``(resource, action)`` right.

    ``action`` may be ``"*"`` to grant every action on a resource. Unknown fields
    are rejected (``extra="forbid"``): constraint-aware capabilities are not
    implemented yet, so a stray ``constraints`` key fails closed rather than being
    silently accepted-but-ignored.
    """

    model_config = {"extra": "forbid"}

    resource: ShortText
    action: ShortText


# --- Registration entries (admin: pre-approve identities) ------------------ #
class RegistrationEntryCreate(BaseModel):
    agent_type: ShortText
    selectors: list[SelectorText] = Field(
        ..., min_length=1, max_length=MAX_SELECTORS_PER_ENTRY
    )
    # Capabilities are the source of truth; legacy ``scopes`` are accepted and
    # parsed into capabilities when no capabilities are given.
    capabilities: list[Capability] = Field(
        default_factory=list, max_length=MAX_CAPABILITIES_PER_ENTRY
    )
    scopes: list[ScopeText] = Field(default_factory=list, max_length=MAX_SCOPES_PER_ENTRY)
    owner: str | None = Field(default=None, max_length=200)
    ttl_seconds: int | None = None
    min_assurance: Literal["low", "standard", "high"] = "standard"
    description: str = Field(default="", max_length=500)


class RegistrationEntryOut(BaseModel):
    id: str
    agent_type: str
    selectors: list[str]
    # Stored capability dicts pass through verbatim (no null constraint noise).
    capabilities: list[dict] = Field(default_factory=list)
    scopes: list[str]
    owner: str | None = None
    ttl_seconds: int | None = None
    min_assurance: str = "standard"
    description: str
    created_at: datetime

    model_config = {"from_attributes": True}


class RegistrationOverlapConflict(BaseModel):
    selector_count: int
    entry_ids: list[str]
    agent_types: list[str]
    selectors: list[list[str]]
    witness_selectors: list[str]
    reason: str


class RegistrationLintWarning(BaseModel):
    entry_id: str
    severity: Literal["warning"]
    reason: str


class RegistrationLintReport(BaseModel):
    ok: bool
    conflicts: list[RegistrationOverlapConflict]
    warnings: list[RegistrationLintWarning] = Field(default_factory=list)


# --- Identity -------------------------------------------------------------- #
class IdentifyRequest(BaseModel):
    """Attestation request. The workload presents a signed attestation document;
    agent_type and scopes are NOT self-declared -- they come from the matched
    registration entry."""

    attestation_document: str = Field(
        ..., min_length=1, max_length=MAX_ATTESTATION_DOCUMENT_CHARS
    )
    ttl_seconds: int | None = None
    # JOSE typ for the minted JWT-SVID. Default "JWT" is the SPIFFE JWT-SVID
    # standard; "wit+jwt" opts into WIMSE Workload Identity Token framing.
    token_typ: Literal["JWT", "wit+jwt"] | None = None
    # Optional EC/RSA public key (SPKI PEM) to also receive an X.509-SVID for
    # mTLS, bound to the same SPIFFE ID. The workload keeps the private key.
    x509_public_key_pem: str | None = Field(default=None, max_length=MAX_PEM_CHARS)
    # Preferred mTLS path: a CSR proves possession of the TLS private key before
    # the service signs the SPIFFE X.509-SVID.
    x509_csr_pem: str | None = Field(default=None, max_length=MAX_PEM_CHARS)


class CredentialOut(BaseModel):
    agent_id: str
    token: str
    spiffe_id: str
    agent_type: str
    owner: str
    capabilities: list[dict] = Field(default_factory=list)
    scopes: list[str]
    selectors: list[str] = Field(default_factory=list)
    # Capability token bound to the workload's SPIFFE keypair (None when the
    # workload presented no public key). ``biscuit_root_public_key`` lets a
    # holder verify/authorize it offline.
    biscuit: str | None = None
    biscuit_root_public_key: str | None = None
    bound_keyhash: str | None = None
    # PEM chain (leaf + signing CA) when an x509_public_key_pem was presented;
    # validate it against GET /t/{tenant}/x509-bundle.
    x509_svid_chain: str | None = None
    expires_at: datetime


class PopIn(BaseModel):
    """Request-bound proof-of-possession from the workload's SPIFFE key."""

    challenge: str = Field(..., min_length=1, max_length=256)
    signature: str = Field(..., min_length=1, max_length=2048)
    pubkey_pem: str = Field(..., min_length=1, max_length=MAX_PEM_CHARS)
    htm: str = Field(..., min_length=1, max_length=16)
    htu: str = Field(..., min_length=1, max_length=2048)
    ath: str = Field(..., min_length=1, max_length=128)
    iat: int
    jti: str = Field(..., min_length=1, max_length=128)


class ValidateRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=MAX_JWT_CHARS)
    pop: PopIn | None = None


class ValidateResponse(BaseModel):
    valid: bool
    claims: dict | None = None


# --- Capability authorization --------------------------------------------- #
class OperationIn(BaseModel):
    resource: ShortText
    action: ShortText


class AuthorizeRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=MAX_CAPABILITY_TOKEN_CHARS)
    operation: OperationIn
    pop: PopIn | None = None


class AuthorizeResponse(BaseModel):
    allowed: bool
    reason: str


class ChallengeResponse(BaseModel):
    challenge: str


# --- Agents (admin/read views) -------------------------------------------- #
class AgentOut(BaseModel):
    id: str
    agent_type: str
    owner: str
    capabilities: list[dict] = Field(default_factory=list)
    scopes: list[str]
    spiffe_id: str | None = None
    selectors: list[str] = Field(default_factory=list)
    bound_keyhash: str | None = None
    has_biscuit: bool = False
    status: str
    issued_at: datetime
    expires_at: datetime

    model_config = {"from_attributes": True}
