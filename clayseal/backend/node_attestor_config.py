"""Build and register cloud node attestors from environment configuration.

The identity service operator decides which clouds/clusters it accepts. Each
attestor is enabled by setting its variables; unset means "not accepted".

- **GCP** (``CLAYSEAL_ATTEST_GCP=1``): no other config — tokens are verified
  against Google's public keys.
- **Kubernetes** (``CLAYSEAL_ATTEST_K8S_CLUSTER=<name>``): also
  ``CLAYSEAL_ATTEST_K8S_API`` (API server URL),
  ``CLAYSEAL_ATTEST_K8S_TOKEN`` or ``..._TOKEN_FILE`` (reviewer SA token), and
  optionally ``CLAYSEAL_ATTEST_K8S_CA`` (cluster CA PEM path).
- **AWS** (``CLAYSEAL_ATTEST_AWS_CERTS=<region>=<pem-path>,...``): map of region
  to the AWS regional public certificate file.
"""
from __future__ import annotations

import os

from .node_attestors import (
    AwsIidAttestor,
    GcpIitAttestor,
    HttpTokenReviewer,
    K8sPsatAttestor,
    register_cloud_attestor,
)


def _truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


def configure_cloud_attestors_from_env() -> list[str]:
    """Register the attestors the environment enables. Returns their type names."""
    enabled: list[str] = []

    if _truthy("CLAYSEAL_ATTEST_GCP"):
        register_cloud_attestor(GcpIitAttestor())
        enabled.append("gcp_iit")

    cluster = os.getenv("CLAYSEAL_ATTEST_K8S_CLUSTER", "").strip()
    if cluster:
        api = os.getenv("CLAYSEAL_ATTEST_K8S_API", "").strip()
        token = os.getenv("CLAYSEAL_ATTEST_K8S_TOKEN", "").strip()
        token_file = os.getenv("CLAYSEAL_ATTEST_K8S_TOKEN_FILE", "").strip()
        if token_file:
            token = _read(token_file)
        ca_file = os.getenv("CLAYSEAL_ATTEST_K8S_CA", "").strip()
        ca_pem = _read(ca_file) if ca_file else None
        if not api or not token:
            raise RuntimeError(
                "CLAYSEAL_ATTEST_K8S_CLUSTER is set but CLAYSEAL_ATTEST_K8S_API and a "
                "reviewer token (CLAYSEAL_ATTEST_K8S_TOKEN or _TOKEN_FILE) are required."
            )
        register_cloud_attestor(
            K8sPsatAttestor(
                reviewer=HttpTokenReviewer(api_server=api, bearer_token=token, ca_pem=ca_pem),
                cluster=cluster,
            )
        )
        enabled.append("k8s_psat")

    aws_certs = os.getenv("CLAYSEAL_ATTEST_AWS_CERTS", "").strip()
    if aws_certs:
        region_certs: dict[str, str] = {}
        for pair in aws_certs.split(","):
            if "=" not in pair:
                continue
            region, cert_path = pair.split("=", 1)
            region_certs[region.strip()] = _read(cert_path.strip())
        if not region_certs:
            raise RuntimeError(
                "CLAYSEAL_ATTEST_AWS_CERTS must be region=cert-path pairs, comma-separated."
            )
        register_cloud_attestor(AwsIidAttestor(region_certs=region_certs))
        enabled.append("aws_iid")

    return enabled
