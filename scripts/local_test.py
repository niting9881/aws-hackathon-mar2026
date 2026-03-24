#!/usr/bin/env python3
"""
Local simulation of the Compliance Drift Detector pipeline.

Runs the full flow without requiring AWS services:
  1. Parses sample Security Hub findings
  2. Simulates resource enrichment
  3. Simulates Bedrock AI analysis
  4. Prints the triaged findings with blast radius scores

Usage:
  python scripts/local_test.py
  python scripts/local_test.py --event sample_events/s3_public_access.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.utils.finding_parser import parse_security_hub_finding, get_finding_category


# ---------------------------------------------------------------------------
# Mock responses (simulate Bedrock and AWS without real calls)
# ---------------------------------------------------------------------------

MOCK_BLAST_RADIUS = {
    "AwsS3Bucket": {
        "blast_radius_score": 9,
        "confidence": 0.92,
        "reasoning": "This S3 bucket 'customer-pii-data-prod' is publicly accessible and contains PII data based on its naming convention and tags. It is in a production environment with cross-service dependencies. Public exposure of PII data would trigger GDPR/CCPA breach notifications and could affect millions of customer records.",
        "risk_factors": [
            "Bucket name suggests PII data",
            "Production environment",
            "No encryption detected",
            "Public read access enabled",
            "Multiple compliance frameworks violated"
        ],
        "affected_services": ["S3", "Lambda", "RDS (downstream)"],
        "data_sensitivity": "pii",
        "exploitability": "likely"
    },
    "AwsEc2SecurityGroup": {
        "blast_radius_score": 8,
        "confidence": 0.88,
        "reasoning": "Security group 'prod-database-sg' allows unrestricted access to MySQL (3306) and SSH (22) from the internet. This directly exposes production database and management ports. Named 'prod-database-sg' suggesting it protects production databases with potentially sensitive data.",
        "risk_factors": [
            "Database port (3306) open to 0.0.0.0/0",
            "SSH (22) open to 0.0.0.0/0",
            "Production security group",
            "Direct internet exposure of database"
        ],
        "affected_services": ["EC2", "RDS"],
        "data_sensitivity": "confidential",
        "exploitability": "likely"
    },
    "AwsIamRole": {
        "blast_radius_score": 7,
        "confidence": 0.85,
        "reasoning": "IAM role 'legacy-deployment-role' has full administrative privileges (Action: *, Resource: *). Legacy roles with excessive permissions are commonly exploited in credential compromise attacks. The role has been active since 2024 suggesting it may be forgotten or under-maintained.",
        "risk_factors": [
            "Full administrative access (Action: *)",
            "Legacy role (created 2024)",
            "No evidence of recent policy review",
            "Could be used for lateral movement"
        ],
        "affected_services": ["All AWS services (wildcard access)"],
        "data_sensitivity": "regulated",
        "exploitability": "possible"
    }
}

MOCK_REMEDIATION = {
    "AwsS3Bucket": {
        "issue_summary": "S3 bucket 'customer-pii-data-prod' allows public read access, exposing potentially sensitive PII data to the internet.",
        "risk_if_unfixed": "Unauthorized parties could download customer PII data, triggering regulatory breach notifications under GDPR, CCPA, and PCI DSS.",
        "remediation_steps": [
            {
                "step_number": 1,
                "description": "Block all public access on the bucket",
                "aws_cli": "aws s3api put-public-access-block --bucket customer-pii-data-prod --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                "is_destructive": False
            },
            {
                "step_number": 2,
                "description": "Enable AES-256 server-side encryption",
                "aws_cli": "aws s3api put-bucket-encryption --bucket customer-pii-data-prod --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"},\"BucketKeyEnabled\":true}]}'",
                "is_destructive": False
            }
        ],
        "cloudformation_snippet": "Type: AWS::S3::Bucket\nProperties:\n  BucketName: customer-pii-data-prod\n  PublicAccessBlockConfiguration:\n    BlockPublicAcls: true\n    IgnorePublicAcls: true\n    BlockPublicPolicy: true\n    RestrictPublicBuckets: true\n  BucketEncryption:\n    ServerSideEncryptionConfiguration:\n      - ServerSideEncryptionByDefault:\n          SSEAlgorithm: AES256",
        "terraform_snippet": "resource \"aws_s3_bucket_public_access_block\" \"block\" {\n  bucket = aws_s3_bucket.customer_pii.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
        "rollback_steps": [
            "aws s3api delete-public-access-block --bucket customer-pii-data-prod"
        ],
        "validation_commands": [
            "aws s3api get-public-access-block --bucket customer-pii-data-prod",
            "aws s3api get-bucket-encryption --bucket customer-pii-data-prod"
        ],
        "estimated_fix_time_minutes": 5,
        "requires_downtime": False
    },
    "AwsEc2SecurityGroup": {
        "issue_summary": "Security group 'prod-database-sg' allows unrestricted ingress on MySQL (3306) and SSH (22) from anywhere on the internet.",
        "risk_if_unfixed": "Direct internet access to database and SSH ports enables brute-force attacks, SQL injection, and unauthorized data extraction.",
        "remediation_steps": [
            {
                "step_number": 1,
                "description": "Revoke the 0.0.0.0/0 ingress rule for MySQL port 3306",
                "aws_cli": "aws ec2 revoke-security-group-ingress --group-id sg-0abc123def456789 --protocol tcp --port 3306 --cidr 0.0.0.0/0",
                "is_destructive": False
            },
            {
                "step_number": 2,
                "description": "Revoke the 0.0.0.0/0 ingress rule for SSH port 22",
                "aws_cli": "aws ec2 revoke-security-group-ingress --group-id sg-0abc123def456789 --protocol tcp --port 22 --cidr 0.0.0.0/0",
                "is_destructive": False
            }
        ],
        "rollback_steps": [
            "aws ec2 authorize-security-group-ingress --group-id sg-0abc123def456789 --protocol tcp --port 3306 --cidr 0.0.0.0/0",
            "aws ec2 authorize-security-group-ingress --group-id sg-0abc123def456789 --protocol tcp --port 22 --cidr 0.0.0.0/0"
        ],
        "validation_commands": [
            "aws ec2 describe-security-groups --group-ids sg-0abc123def456789 --query 'SecurityGroups[0].IpPermissions'"
        ],
        "estimated_fix_time_minutes": 3,
        "requires_downtime": False
    },
    "AwsIamRole": {
        "issue_summary": "IAM role 'legacy-deployment-role' has full admin access (Action: *, Resource: *), violating least-privilege principles.",
        "risk_if_unfixed": "If compromised, this role provides unrestricted access to all AWS services and data across the account.",
        "remediation_steps": [
            {
                "step_number": 1,
                "description": "Detach the AdministratorAccess managed policy",
                "aws_cli": "aws iam detach-role-policy --role-name legacy-deployment-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                "is_destructive": True
            }
        ],
        "rollback_steps": [
            "aws iam attach-role-policy --role-name legacy-deployment-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ],
        "validation_commands": [
            "aws iam list-attached-role-policies --role-name legacy-deployment-role"
        ],
        "estimated_fix_time_minutes": 10,
        "requires_downtime": False
    }
}


def run_simulation(event_path: str):
    """Run the full pipeline simulation on a sample event."""
    print("=" * 70)
    print("  AI COMPLIANCE DRIFT DETECTOR — LOCAL SIMULATION")
    print("=" * 70)
    print()

    # Load event
    with open(event_path) as f:
        event = json.load(f)

    print(f"📄 Loaded event: {event_path}")
    print()

    # Step 1: Parse
    print("━" * 70)
    print("STEP 1: Parse ASFF Finding")
    print("━" * 70)
    parsed = parse_security_hub_finding(event)
    finding = parsed["findings"][0]
    print(f"  Title:      {finding['title']}")
    print(f"  Resource:   {finding['resource_id']} ({finding['resource_type']})")
    print(f"  Account:    {finding['account_id']}")
    print(f"  Region:     {finding['resource_region']}")
    print(f"  Severity:   {finding['severity_label']} ({finding['severity_normalized']})")
    print(f"  Framework:  {finding['compliance_framework']}")
    print(f"  Category:   {get_finding_category(finding)}")
    print()

    # Step 2: Enrich (simulated)
    print("━" * 70)
    print("STEP 2: Resource Enrichment (simulated)")
    print("━" * 70)
    resource_type = finding["resource_type"]
    print(f"  Fetching tags for {finding['resource_arn']}...")
    print(f"  Fetching {resource_type} configuration details...")
    print(f"  ✓ Resource context enriched")
    print()

    # Step 3: AI Blast Radius Scoring (simulated)
    print("━" * 70)
    print("STEP 3: AI Blast Radius Scoring (Bedrock — simulated)")
    print("━" * 70)
    blast = MOCK_BLAST_RADIUS.get(resource_type, MOCK_BLAST_RADIUS["AwsS3Bucket"])
    score = blast["blast_radius_score"]
    icon = "🔴" if score >= 8 else "🟠" if score >= 5 else "🟡" if score >= 3 else "🟢"
    print(f"  {icon} Blast Radius: {score}/10 (confidence: {blast['confidence']})")
    print(f"  Reasoning: {blast['reasoning']}")
    print(f"  Data sensitivity: {blast['data_sensitivity']}")
    print(f"  Exploitability: {blast['exploitability']}")
    print(f"  Risk factors:")
    for rf in blast["risk_factors"]:
        print(f"    • {rf}")
    print()

    # Step 4: AI Remediation (simulated)
    print("━" * 70)
    print("STEP 4: AI Remediation Generation (Bedrock — simulated)")
    print("━" * 70)
    remediation = MOCK_REMEDIATION.get(resource_type, MOCK_REMEDIATION["AwsS3Bucket"])
    print(f"  Summary: {remediation['issue_summary']}")
    print(f"  Risk if unfixed: {remediation['risk_if_unfixed']}")
    print(f"  Fix time: ~{remediation['estimated_fix_time_minutes']} minutes")
    print(f"  Downtime required: {'Yes' if remediation['requires_downtime'] else 'No'}")
    print()
    print(f"  Remediation steps:")
    for step in remediation["remediation_steps"]:
        destructive = " ⚠️  DESTRUCTIVE" if step["is_destructive"] else ""
        print(f"    {step['step_number']}. {step['description']}{destructive}")
        print(f"       $ {step['aws_cli'][:100]}...")
    print()
    print(f"  Validation:")
    for cmd in remediation["validation_commands"]:
        print(f"    $ {cmd}")
    print()

    # Step 5: Decision
    print("━" * 70)
    print("STEP 5: Workflow Decision")
    print("━" * 70)
    threshold = 7
    if score >= threshold:
        print(f"  ⚡ Score {score} >= threshold {threshold}")
        print(f"  → STARTING REMEDIATION WORKFLOW (requires human approval)")
        print(f"  → Approval request sent to SNS/Slack")
    elif score >= 4:
        print(f"  📋 Score {score} between 4-{threshold-1}")
        print(f"  → Triaged and queued for review")
    else:
        print(f"  ✅ Score {score} < 4")
        print(f"  → Auto-approved for remediation")
    print()

    # Summary
    print("=" * 70)
    print("  SIMULATION COMPLETE")
    print("=" * 70)
    print(f"  Finding:  {finding['title'][:50]}...")
    print(f"  Resource: {finding['resource_id']}")
    print(f"  Score:    {icon} {score}/10")
    print(f"  Status:   {'WORKFLOW_STARTED' if score >= threshold else 'TRIAGED'}")
    print()

    return {
        "finding": finding,
        "blast_radius": blast,
        "remediation": remediation,
    }


def run_all_samples():
    """Run simulation on all sample events."""
    sample_dir = os.path.join(os.path.dirname(__file__), "..", "sample_events")
    for fname in sorted(os.listdir(sample_dir)):
        if fname.endswith(".json"):
            path = os.path.join(sample_dir, fname)
            run_simulation(path)
            print("\n" * 2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run local compliance drift detector simulation")
    parser.add_argument(
        "--event",
        type=str,
        help="Path to a specific event JSON file (default: run all samples)",
    )
    args = parser.parse_args()

    if args.event:
        run_simulation(args.event)
    else:
        run_all_samples()
