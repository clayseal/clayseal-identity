from agentauth.identity.adapters import get_identity_adapter, list_identity_adapters


def test_l1_identity_adapters_are_standalone():
    names = list_identity_adapters()
    assert {"oidc", "spiffe_jwt", "static", "azure_ad", "gcp_service_account"}.issubset(
        names
    )


def test_oidc_adapter_normalizes_claims():
    binding = get_identity_adapter("oidc").to_binding(
        {
            "sub": "agent-1",
            "iss": "https://issuer.example",
            "scope": "db:read api:write",
            "org_id": "org_demo",
            "email": "bot@example.com",
        }
    )
    assert binding.subject_id == "agent-1"
    assert binding.scopes == ["db:read", "api:write"]
    assert binding.tenant_id == "org_demo"
    assert binding.to_claims()["iss"] == "https://issuer.example"


def test_static_adapter_supports_identity_only_substitution():
    binding = get_identity_adapter("static").to_binding(
        {"subject_id": "local-agent", "issuer": "unit", "scopes": ["tool:call"]}
    )
    assert binding.subject_id == "local-agent"
    assert binding.issuer == "unit"
    assert binding.scopes == ["tool:call"]


def test_azure_adapter_normalizes_workload_claims():
    binding = get_identity_adapter("azure_ad").to_binding(
        {
            "oid": "obj-123",
            "tid": "tenant-123",
            "iss": "https://sts.windows.net/tenant-123/",
            "scp": "api.read api.write",
            "roles": ["Agent.Executor"],
            "appid": "app-123",
        }
    )
    assert binding.subject_id == "obj-123"
    assert binding.tenant_id == "tenant-123"
    assert "Agent.Executor" in binding.scopes


def test_gcp_adapter_normalizes_service_account_claims():
    binding = get_identity_adapter("gcp_service_account").to_binding(
        {
            "email": "agent@project.iam.gserviceaccount.com",
            "project_id": "project-1",
            "scope": "cloud-platform",
        }
    )
    assert binding.subject_id == "agent@project.iam.gserviceaccount.com"
    assert binding.tenant_id == "project-1"
    assert binding.subject_type == "gcp_service_account"
