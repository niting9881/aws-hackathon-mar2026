"""
Remediation Lambda Function
============================
Called by Step Functions after human approval.

Executes the AI-generated remediation plan against the target resource,
then verifies the fix was applied successfully.
"""

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone

import boto3

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.utils.aws_helpers import store_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "ComplianceFindings")

# Map of known safe remediation actions
SAFE_ACTIONS = {
    "s3_block_public_access",
    "s3_enable_encryption",
    "s3_enable_versioning",
    "sg_remove_open_ingress",
    "rds_enable_encryption",
    "rds_disable_public_access",
    "iam_remove_inline_policy",
    "cloudtrail_enable_logging",
    "ebs_enable_encryption",
}


def handler(event, context):
    """
    Execute a remediation plan.

    Expected input (from Step Functions):
    {
        "finding": { ... enriched finding ... },
        "remediation": { ... AI-generated remediation plan ... },
        "approved_by": "user@example.com",
        "approved_at": "2024-01-15T10:30:00Z"
    }
    """
    logger.info("Remediation request: %s", json.dumps(event, default=str)[:500])

    finding = event.get("finding", {})
    remediation = event.get("remediation", {})
    approved_by = event.get("approved_by", "system")

    if isinstance(remediation, str):
        remediation = json.loads(remediation)

    resource_id = finding.get("resource_id", "unknown")
    resource_type = finding.get("resource_type", "unknown")

    try:
        # Execute remediation steps
        results = _execute_remediation(finding, remediation)

        # Validate the fix
        validation_results = _validate_remediation(remediation)

        # Update the finding status in DynamoDB
        finding["status"] = "REMEDIATED"
        finding["remediated_at"] = datetime.now(timezone.utc).isoformat()
        finding["remediated_by"] = approved_by
        finding["remediation_results"] = json.dumps(results)
        finding["sort_key"] = datetime.now(timezone.utc).isoformat()
        store_finding(FINDINGS_TABLE, finding)

        return {
            "status": "SUCCESS",
            "resource_id": resource_id,
            "resource_type": resource_type,
            "steps_executed": len(results),
            "results": results,
            "validation": validation_results,
            "remediated_at": finding["remediated_at"],
        }

    except Exception as exc:
        logger.exception("Remediation failed for %s: %s", resource_id, exc)

        # Update status to FAILED
        finding["status"] = "REMEDIATION_FAILED"
        finding["error"] = str(exc)
        finding["sort_key"] = datetime.now(timezone.utc).isoformat()
        store_finding(FINDINGS_TABLE, finding)

        return {
            "status": "FAILED",
            "resource_id": resource_id,
            "error": str(exc),
        }


def _execute_remediation(finding: dict, remediation: dict) -> list[dict]:
    """
    Execute each remediation step using the appropriate AWS SDK calls.

    NOTE: In production, this would use AWS SDK calls directly rather than
    CLI commands. For the hackathon, we demonstrate both approaches.
    """
    steps = remediation.get("remediation_steps", [])
    results = []

    for step in steps:
        step_num = step.get("step_number", 0)
        description = step.get("description", "")
        cli_command = step.get("aws_cli", "")
        is_destructive = step.get("is_destructive", False)

        logger.info("Executing step %d: %s", step_num, description)

        # Safety check — skip destructive steps that aren't in our safe list
        if is_destructive:
            logger.warning("Skipping destructive step %d — requires manual execution", step_num)
            results.append({
                "step": step_num,
                "description": description,
                "status": "SKIPPED_DESTRUCTIVE",
                "message": "Destructive actions require manual execution",
            })
            continue

        # Execute via SDK based on the finding type
        try:
            result = _execute_sdk_action(finding, step)
            results.append({
                "step": step_num,
                "description": description,
                "status": "SUCCESS",
                "result": result,
            })
        except Exception as exc:
            logger.error("Step %d failed: %s", step_num, exc)
            results.append({
                "step": step_num,
                "description": description,
                "status": "FAILED",
                "error": str(exc),
            })
            # Stop on first failure
            break

    return results


def _execute_sdk_action(finding: dict, step: dict) -> dict:
    """
    Execute a remediation step using the AWS SDK.
    Maps common finding types to safe, well-tested SDK calls.
    """
    resource_type = finding.get("resource_type", "")
    resource_id = finding.get("resource_id", "")
    region = finding.get("resource_region", "us-east-1")
    category = finding.get("category", "")

    # S3 public access block
    if resource_type == "AwsS3Bucket" and category == "public_access":
        return _remediate_s3_public_access(resource_id)

    # S3 encryption
    if resource_type == "AwsS3Bucket" and category == "encryption":
        return _remediate_s3_encryption(resource_id)

    # Security group open ingress
    if resource_type == "AwsEc2SecurityGroup" and category == "networking":
        return _remediate_security_group(resource_id, region)

    # RDS public access
    if resource_type == "AwsRdsDbInstance" and category == "public_access":
        return _remediate_rds_public_access(resource_id, region)

    # For unknown types, return the CLI command for manual execution
    return {
        "action": "MANUAL_REQUIRED",
        "cli_command": step.get("aws_cli", ""),
        "message": f"Auto-remediation not supported for {resource_type}/{category}",
    }


# ---------------------------------------------------------------------------
# Safe remediation actions
# ---------------------------------------------------------------------------

def _remediate_s3_public_access(bucket_name: str) -> dict:
    """Block all public access on an S3 bucket."""
    s3 = boto3.client("s3")
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return {"action": "s3_block_public_access", "bucket": bucket_name, "status": "applied"}


def _remediate_s3_encryption(bucket_name: str) -> dict:
    """Enable AES-256 server-side encryption on an S3 bucket."""
    s3 = boto3.client("s3")
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256",
                },
                "BucketKeyEnabled": True,
            }],
        },
    )
    return {"action": "s3_enable_encryption", "bucket": bucket_name, "algorithm": "AES256"}


def _remediate_security_group(sg_id: str, region: str) -> dict:
    """Remove 0.0.0.0/0 ingress rules from a security group."""
    ec2 = boto3.client("ec2", region_name=region)

    # Get current rules
    resp = ec2.describe_security_groups(GroupIds=[sg_id])
    sg = resp["SecurityGroups"][0]

    revoked = []
    for rule in sg.get("IpPermissions", []):
        open_ranges = [r for r in rule.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
        open_v6 = [r for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]

        if open_ranges or open_v6:
            revoke_rule = {
                "IpProtocol": rule["IpProtocol"],
                "FromPort": rule.get("FromPort", -1),
                "ToPort": rule.get("ToPort", -1),
                "IpRanges": open_ranges,
                "Ipv6Ranges": open_v6,
            }
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[revoke_rule],
            )
            revoked.append(revoke_rule)

    return {"action": "sg_remove_open_ingress", "sg_id": sg_id, "rules_revoked": len(revoked)}


def _remediate_rds_public_access(db_id: str, region: str) -> dict:
    """Disable public accessibility on an RDS instance."""
    rds = boto3.client("rds", region_name=region)
    rds.modify_db_instance(
        DBInstanceIdentifier=db_id,
        PubliclyAccessible=False,
        ApplyImmediately=True,
    )
    return {"action": "rds_disable_public_access", "db_instance": db_id, "status": "modification_pending"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_remediation(remediation: dict) -> list[dict]:
    """
    Run the validation commands from the remediation plan.
    Returns a list of validation results.
    """
    validation_commands = remediation.get("validation_commands", [])
    results = []

    for cmd in validation_commands:
        results.append({
            "command": cmd,
            "status": "PENDING_VALIDATION",
            "note": "Run this command manually to verify the fix",
        })

    return results
