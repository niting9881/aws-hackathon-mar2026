"""
Triage Lambda Function
======================
Triggered by EventBridge when Security Hub publishes new findings.

Flow:
  1. Parse ASFF finding from the event
  2. Enrich with resource metadata and tags
  3. Fetch drift history from DynamoDB
  4. Call Bedrock for blast radius scoring
  5. Generate remediation script
  6. Store enriched finding in DynamoDB
  7. If score >= threshold → start Step Functions remediation workflow
  8. Send notification via SNS
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

# Add parent directory to path for shared imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.utils.finding_parser import parse_security_hub_finding, get_finding_category
from src.utils.aws_helpers import (
    get_resource_tags,
    get_resource_details,
    store_finding,
    get_finding_history,
    send_sns_notification,
)
from src.bedrock.analyzer import score_blast_radius, generate_remediation

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "ComplianceFindings")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN", "")
BLAST_RADIUS_THRESHOLD = int(os.environ.get("BLAST_RADIUS_THRESHOLD", "7"))

sfn_client = boto3.client("stepfunctions")


def handler(event, context):
    """
    Lambda handler — entry point for EventBridge Security Hub findings.
    """
    logger.info("Received event: %s", json.dumps(event, default=str)[:1000])

    try:
        # 1. Parse the ASFF finding
        parsed = parse_security_hub_finding(event)
        findings = parsed["findings"]
        logger.info("Parsed %d finding(s) from event", len(findings))

        results = []
        for finding in findings:
            result = _process_single_finding(finding)
            results.append(result)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": f"Processed {len(results)} finding(s)",
                "results": results,
            }, default=str),
        }

    except Exception as exc:
        logger.exception("Error processing finding: %s", exc)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(exc)}),
        }


def _process_single_finding(finding: dict) -> dict:
    """Process a single compliance finding through the AI pipeline."""

    resource_arn = finding["resource_arn"]
    resource_type = finding["resource_type"]
    resource_id = finding["resource_id"]
    resource_region = finding["resource_region"]
    account_id = finding["account_id"]

    logger.info(
        "Processing finding: %s for %s (%s)",
        finding["title"],
        resource_id,
        resource_type,
    )

    # 2. Enrich with resource metadata
    tags = get_resource_tags(resource_arn)
    resource_context = get_resource_details(resource_type, resource_id, resource_region)
    resource_context["tags"] = tags

    # Determine data sensitivity from tags
    data_classification = tags.get("data-classification", tags.get("DataClassification", "unknown"))
    environment = tags.get("environment", tags.get("Environment", "unknown"))
    resource_context["data_classification"] = data_classification
    resource_context["environment"] = environment

    # 3. Fetch drift history
    drift_history = get_finding_history(FINDINGS_TABLE, resource_id, limit=10)

    # 4. AI: Blast radius scoring
    blast_result = score_blast_radius(finding, resource_context, drift_history)
    blast_score = blast_result.get("blast_radius_score", 5)

    logger.info(
        "Blast radius for %s: %d/10 — %s",
        resource_id,
        blast_score,
        blast_result.get("reasoning", ""),
    )

    # 5. AI: Generate remediation
    remediation = generate_remediation(finding, resource_context)

    # 6. Build the enriched finding record
    enriched_finding = {
        "finding_id": finding["finding_id"],
        "dedup_key": finding["dedup_key"],
        "resource_id": resource_id,
        "resource_arn": resource_arn,
        "resource_type": resource_type,
        "resource_region": resource_region,
        "account_id": account_id,
        "title": finding["title"],
        "description": finding["description"],
        "category": get_finding_category(finding),
        "severity_label": finding["severity_label"],
        "severity_normalized": finding["severity_normalized"],
        "compliance_framework": finding["compliance_framework"],
        "blast_radius_score": blast_score,
        "blast_radius_confidence": blast_result.get("confidence", 0),
        "blast_radius_reasoning": blast_result.get("reasoning", ""),
        "risk_factors": json.dumps(blast_result.get("risk_factors", [])),
        "data_sensitivity": blast_result.get("data_sensitivity", "unknown"),
        "exploitability": blast_result.get("exploitability", "unknown"),
        "remediation_summary": remediation.get("issue_summary", ""),
        "remediation_plan": json.dumps(remediation),
        "environment": environment,
        "status": "TRIAGED",
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "sort_key": datetime.now(timezone.utc).isoformat(),
    }

    # 7. Store in DynamoDB
    store_finding(FINDINGS_TABLE, enriched_finding)

    # 8. If blast radius >= threshold, start remediation workflow
    if blast_score >= BLAST_RADIUS_THRESHOLD and STATE_MACHINE_ARN:
        _start_remediation_workflow(enriched_finding, remediation)

    # 9. Send notification
    if SNS_TOPIC_ARN:
        _send_finding_notification(enriched_finding, blast_result)

    return {
        "finding_id": finding["finding_id"],
        "resource_id": resource_id,
        "blast_radius_score": blast_score,
        "status": "WORKFLOW_STARTED" if blast_score >= BLAST_RADIUS_THRESHOLD else "TRIAGED",
    }


def _start_remediation_workflow(finding: dict, remediation: dict) -> None:
    """Start the Step Functions remediation workflow."""
    try:
        sfn_client.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=f"remediate-{finding['dedup_key']}-{int(datetime.now(timezone.utc).timestamp())}",
            input=json.dumps({
                "finding": finding,
                "remediation": remediation,
                "requires_approval": True,
                "auto_approve_below_score": 4,
            }, default=str),
        )
        logger.info("Started remediation workflow for %s", finding["resource_id"])
    except Exception as exc:
        logger.error("Failed to start workflow: %s", exc)


def _send_finding_notification(finding: dict, blast_result: dict) -> None:
    """Send a formatted SNS notification about the finding."""
    score = finding["blast_radius_score"]
    emoji = "🔴" if score >= 8 else "🟠" if score >= 5 else "🟡"

    subject = f"{emoji} [{score}/10] Compliance drift: {finding['title'][:60]}"
    message = f"""
AWS Compliance Drift Detected
{'=' * 50}

Resource:     {finding['resource_id']} ({finding['resource_type']})
Account:      {finding['account_id']}
Region:       {finding['resource_region']}
Environment:  {finding.get('environment', 'unknown')}
Framework:    {finding['compliance_framework']}
Severity:     {finding['severity_label']}

AI Analysis
{'-' * 50}
Blast Radius: {score}/10
Confidence:   {blast_result.get('confidence', 'N/A')}
Data Risk:    {blast_result.get('data_sensitivity', 'unknown')}
Exploitable:  {blast_result.get('exploitability', 'unknown')}

Reasoning:
{blast_result.get('reasoning', 'N/A')}

Risk Factors:
{chr(10).join('  • ' + f for f in blast_result.get('risk_factors', []))}

Quick Fix:
{finding.get('remediation_summary', 'See remediation plan for details.')}

Status: {'⚡ REMEDIATION WORKFLOW STARTED' if score >= BLAST_RADIUS_THRESHOLD else '📋 Triaged — awaiting manual review'}
"""

    try:
        send_sns_notification(SNS_TOPIC_ARN, subject, message.strip())
    except Exception as exc:
        logger.error("Failed to send notification: %s", exc)
