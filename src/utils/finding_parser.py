"""
Parser for AWS Security Finding Format (ASFF) events.
Normalizes findings from Security Hub, Config, GuardDuty, and Inspector
into a unified internal representation.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def parse_security_hub_finding(event: dict) -> dict:
    """
    Parse a Security Hub finding (ASFF format) into our internal schema.

    Handles both:
      - EventBridge events (detail.findings[])
      - Direct Security Hub finding objects
    """
    # Unwrap EventBridge envelope if present
    if "detail" in event and "findings" in event["detail"]:
        findings = event["detail"]["findings"]
    elif "findings" in event:
        findings = event["findings"]
    elif "Id" in event and "ProductArn" in event:
        findings = [event]
    else:
        raise ValueError("Unrecognized event format — expected ASFF finding")

    parsed = []
    for f in findings:
        parsed.append(_normalize_finding(f))

    return {"findings": parsed, "count": len(parsed)}


def _normalize_finding(f: dict) -> dict:
    """Map ASFF fields to our internal finding representation."""
    resources = f.get("Resources", [{}])
    first_resource = resources[0] if resources else {}

    severity = f.get("Severity", {})
    severity_label = severity.get("Label", "INFORMATIONAL")
    severity_normalized = severity.get("Normalized", 0)

    compliance_status = (
        f.get("Compliance", {}).get("Status", "NOT_AVAILABLE")
    )

    resource_arn = first_resource.get("Id", "unknown")
    resource_type = first_resource.get("Type", "Other")
    resource_region = first_resource.get("Region", "us-east-1")

    # Extract resource name from ARN or Id
    resource_id = _extract_resource_id(resource_arn, resource_type)

    # Build a stable dedup key
    dedup_key = _build_dedup_key(
        f.get("GeneratorId", ""),
        resource_arn,
        f.get("Title", ""),
    )

    return {
        "finding_id": f.get("Id", ""),
        "dedup_key": dedup_key,
        "generator_id": f.get("GeneratorId", ""),
        "product_arn": f.get("ProductArn", ""),
        "title": f.get("Title", ""),
        "description": f.get("Description", ""),
        "severity_label": severity_label,
        "severity_normalized": severity_normalized,
        "compliance_status": compliance_status,
        "compliance_framework": _extract_framework(f),
        "resource_arn": resource_arn,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_region": resource_region,
        "resource_details": first_resource.get("Details", {}),
        "account_id": f.get("AwsAccountId", ""),
        "recommendation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
        "recommendation_url": f.get("Remediation", {}).get("Recommendation", {}).get("Url", ""),
        "record_state": f.get("RecordState", "ACTIVE"),
        "workflow_status": f.get("Workflow", {}).get("Status", "NEW"),
        "first_observed_at": f.get("FirstObservedAt", ""),
        "last_observed_at": f.get("LastObservedAt", ""),
        "created_at": f.get("CreatedAt", ""),
        "updated_at": f.get("UpdatedAt", ""),
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }


def _extract_resource_id(arn: str, resource_type: str) -> str:
    """Pull a human-readable resource identifier from an ARN."""
    if arn.startswith("arn:"):
        parts = arn.split(":")
        # Last part often contains the resource identifier
        resource_part = parts[-1] if len(parts) >= 6 else arn
        # Handle / separators (e.g. role/MyRole, bucket/my-bucket)
        if "/" in resource_part:
            return resource_part.split("/")[-1]
        return resource_part

    return arn


def _extract_framework(finding: dict) -> str:
    """Attempt to extract the compliance framework name."""
    generator = finding.get("GeneratorId", "")

    framework_keywords = {
        "cis-aws": "CIS AWS Foundations",
        "pci-dss": "PCI DSS",
        "aws-foundational": "AWS Foundational Security Best Practices",
        "nist": "NIST 800-53",
        "soc2": "SOC 2",
        "hipaa": "HIPAA",
    }

    generator_lower = generator.lower()
    for keyword, name in framework_keywords.items():
        if keyword in generator_lower:
            return name

    return "General"


def _build_dedup_key(generator_id: str, resource_arn: str, title: str) -> str:
    """Create a stable hash for deduplication."""
    raw = f"{generator_id}|{resource_arn}|{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_finding_category(finding: dict) -> str:
    """Classify a finding into a high-level category."""
    title_lower = finding.get("title", "").lower()
    resource_type = finding.get("resource_type", "")

    categories = {
        "encryption": ["encrypt", "kms", "ssl", "tls", "at rest", "in transit"],
        "public_access": ["public", "open to", "0.0.0.0", "unrestricted"],
        "iam_permissions": ["iam", "permission", "policy", "role", "admin", "privilege"],
        "logging": ["logging", "trail", "monitor", "flow log", "audit"],
        "networking": ["security group", "nacl", "vpc", "subnet", "firewall"],
        "data_protection": ["backup", "versioning", "retention", "deletion"],
        "patch_management": ["patch", "update", "version", "deprecated", "end of life"],
    }

    for category, keywords in categories.items():
        if any(kw in title_lower for kw in keywords):
            return category

    if "S3" in resource_type:
        return "data_protection"
    if "Iam" in resource_type:
        return "iam_permissions"
    if "Ec2" in resource_type or "SecurityGroup" in resource_type:
        return "networking"

    return "general"
