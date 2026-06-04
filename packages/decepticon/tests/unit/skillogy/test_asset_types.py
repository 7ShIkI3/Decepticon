"""Skillogy AssetType seed coverage tests."""

from __future__ import annotations

from decepticon.skillogy.builder.seeds import load_asset_types
from decepticon.skillogy.builder.seeds_to_graph import emit_asset_type_records

REQUESTED_ASSET_TYPE_COVERAGE: dict[str, str] = {
    "CIDR": "cidr",
    "Domain": "domain",
    "iOS App Store": "ios-app-store",
    "iOS TestFlight": "ios-testflight",
    "iOS IPA": "ios-ipa",
    "Android Play Store": "android-play-store",
    "Android APK": "android-apk",
    "Windows Microsoft Store": "windows-microsoft-store",
    "Source Code": "source-code",
    "Executable": "executable",
    "Smart Contract": "smart-contract",
    "Wildcard": "wildcard",
    "IP Address": "ip-address",
    "Hardware / IoT": "hardware-iot",
    "Other Asset": "other-asset",
    "AI Model": "ai-model",
    "API": "api",
    "AWS Account": "aws-account",
    "Azure Account": "azure-account",
    "Blockchain": "blockchain",
    "DLT": "dlt",
    "URL": "url",
    "Subdomain": "subdomain",
    "GraphQL Endpoint": "api-graphql",
    "WebSocket": "websocket",
    "gRPC Service": "grpc-service",
    "REST API Endpoint": "api-rest",
    "OAuth / SSO Provider": "oauth-sso-provider",
    "VPN / Remote Access Gateway": "vpn",
    "CDN / Edge Infrastructure": "cdn-edge-infrastructure",
    "DNS Infrastructure": "dns-infrastructure",
    "GCP Account / Project": "gcp-project",
    "Google Workspace": "google-workspace",
    "Microsoft 365 / Office 365 Tenant": "m365-tenant",
    "AWS S3 Bucket / Storage Object": "aws-s3",
    "Azure Blob / Storage": "azure-blob",
    "Docker Registry / Container Image": "docker-registry",
    "Kubernetes Cluster / API Server": "kubernetes",
    "CI/CD Pipeline": "ci-cd-pipeline",
    "Serverless Function": "serverless-function",
    "Container / VM Image": "vm-container-image",
    "macOS Application": "macos-application",
    "Linux Binary / Package": "linux-binary-package",
    "Electron Desktop App": "electron-desktop-app",
    "Browser Extension": "browser-extension",
    "Firmware": "firmware",
    "Blockchain Node / Client": "blockchain-node",
    "DeFi Protocol / dApp": "defi-protocol",
    "NFT / Token Contract": "token-contract",
    "Bridge / Cross-chain Infrastructure": "cross-chain-bridge",
    "Oracle Integration": "oracle-integration",
    "Wallet": "crypto-wallet",
    "Cryptographic Library / Primitive": "cryptographic-library",
    "LLM Safety Classifier / Alignment Layer": "llm-safety-classifier",
    "ML Model Weights / Artifact": "ml-model-artifact",
    "AI Inference Endpoint": "ai-inference-endpoint",
    "Training Data Pipeline": "training-data-pipeline",
    "SAML / OIDC Identity Provider": "saml-oidc-idp",
    "SSO / LDAP / Active Directory Integration": "sso-ldap-ad-integration",
    "Hardware Security Key / FIDO2 Implementation": "fido2-implementation",
    "Certificate Authority / PKI Infrastructure": "ca-pki-infrastructure",
    "ASN": "asn",
    "OT / SCADA / ICS": "ics-ot",
    "Physical Facility / Access Control System": "physical-facility-access-control",
    "Network Device": "network-device",
    "Satellite / Radio / RF Interface": "satellite-radio-rf-interface",
    "Database Exposed Instance": "exposed-database",
    "Data Warehouse / Analytics Platform": "data-warehouse",
    "Secrets Manager / Vault": "secrets-manager",
    "Backup / Snapshot Storage": "backup-snapshot-storage",
    "Email Infrastructure": "email-infrastructure",
    "Chat / Messaging Platform Integration": "chat-messaging-integration",
    "SDK / Client Library": "sdk-client-library",
    "Webhook Endpoint": "webhook-endpoint",
    "Third-party Integration / Plugin / OAuth App": "third-party-integration",
}


def test_asset_type_seed_covers_requested_asset_and_domain_types() -> None:
    names = {asset_type.name for asset_type in load_asset_types()}

    missing = {
        requested: slug
        for requested, slug in REQUESTED_ASSET_TYPE_COVERAGE.items()
        if slug not in names
    }

    assert missing == {}


def test_asset_type_graph_emits_subtype_edge_for_each_non_root_seed() -> None:
    seeds = load_asset_types()
    _, edges = emit_asset_type_records()

    non_root_seeds = {asset_type.name for asset_type in seeds if asset_type.category != "root"}
    child_names_with_edges = {edge.to_key for edge in edges if edge.edge_type == "HAS_SUBTYPE"}

    assert child_names_with_edges == non_root_seeds
