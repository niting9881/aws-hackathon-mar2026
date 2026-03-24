"""
Notifier Lambda Function
=========================
Sends rich notifications to Slack and email when findings
are triaged or remediation workflows complete.
"""

import json
import logging
import os
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")


def handler(event, context):
    """
    Send notifications about finding triage or remediation results.

    Supports two event types:
      - "finding_triaged": New finding processed by the AI
      - "remediation_complete": A remediation workflow finished
    """
    logger.info("Notification event: %s", json.dumps(event, default=str)[:500])

    event_type = event.get("event_type", "finding_triaged")
    finding = event.get("finding", {})

    if event_type == "finding_triaged":
        message = _format_triage_notification(finding, event)
    elif event_type == "remediation_complete":
        message = _format_remediation_notification(finding, event)
    else:
        message = _format_generic_notification(event)

    # Send to Slack if configured
    if SLACK_WEBHOOK_URL:
        _send_slack(message["slack"])

    # Send to SNS if configured
    if SNS_TOPIC_ARN:
        _send_sns(message["subject"], message["text"])

    return {"status": "sent", "channels": _active_channels()}


# ---------------------------------------------------------------------------
# Message formatters
# ---------------------------------------------------------------------------

def _format_triage_notification(finding: dict, event: dict) -> dict:
    """Format a Slack Block Kit message for a triaged finding."""
    score = finding.get("blast_radius_score", 0)
    color = _score_color(score)
    icon = _score_icon(score)

    slack_blocks = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{icon} Compliance Drift Detected [{score}/10]",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Resource:*\n`{finding.get('resource_id', 'N/A')}`"},
                        {"type": "mrkdwn", "text": f"*Type:*\n{finding.get('resource_type', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*Account:*\n{finding.get('account_id', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*Region:*\n{finding.get('resource_region', 'N/A')}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Finding:* {finding.get('title', 'N/A')}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Blast Radius:* {score}/10"},
                        {"type": "mrkdwn", "text": f"*Severity:* {finding.get('severity_label', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*Data Risk:* {finding.get('data_sensitivity', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*Framework:* {finding.get('compliance_framework', 'N/A')}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*AI Analysis:*\n{finding.get('blast_radius_reasoning', 'N/A')}",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Quick Fix:*\n{finding.get('remediation_summary', 'See full plan')}",
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Approve Remediation"},
                            "style": "primary",
                            "action_id": "approve_remediation",
                            "value": finding.get("finding_id", ""),
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Dismiss"},
                            "action_id": "dismiss_finding",
                            "value": finding.get("finding_id", ""),
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View Details"},
                            "action_id": "view_details",
                            "value": finding.get("finding_id", ""),
                        },
                    ],
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Processed at {finding.get('processed_at', 'N/A')} | "
                                    f"Environment: {finding.get('environment', 'unknown')}",
                        },
                    ],
                },
            ],
        }],
    }

    subject = f"{icon} [{score}/10] {finding.get('title', 'Compliance drift')[:70]}"
    text = _format_email_body(finding)

    return {"slack": slack_blocks, "subject": subject, "text": text}


def _format_remediation_notification(finding: dict, event: dict) -> dict:
    """Format notification for a completed remediation."""
    status = event.get("remediation_status", "UNKNOWN")
    is_success = status == "SUCCESS"
    icon = "✅" if is_success else "❌"

    slack_blocks = {
        "attachments": [{
            "color": "#28a745" if is_success else "#dc3545",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{icon} Remediation {'Complete' if is_success else 'Failed'}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Resource:*\n`{finding.get('resource_id', 'N/A')}`"},
                        {"type": "mrkdwn", "text": f"*Status:*\n{status}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Details:*\n{event.get('details', 'No additional details')}",
                    },
                },
            ],
        }],
    }

    subject = f"{icon} Remediation {status}: {finding.get('resource_id', 'N/A')}"
    text = f"Remediation {status} for {finding.get('resource_id', 'N/A')}\n{event.get('details', '')}"

    return {"slack": slack_blocks, "subject": subject, "text": text}


def _format_generic_notification(event: dict) -> dict:
    slack_blocks = {
        "text": json.dumps(event, indent=2, default=str)[:3000],
    }
    return {"slack": slack_blocks, "subject": "Compliance alert", "text": json.dumps(event, default=str)}


def _format_email_body(finding: dict) -> str:
    return f"""
Compliance Drift Detected
{'=' * 50}

Resource: {finding.get('resource_id', 'N/A')} ({finding.get('resource_type', 'N/A')})
Account:  {finding.get('account_id', 'N/A')}
Region:   {finding.get('resource_region', 'N/A')}
Severity: {finding.get('severity_label', 'N/A')}

AI Analysis:
  Blast Radius: {finding.get('blast_radius_score', 'N/A')}/10
  Reasoning: {finding.get('blast_radius_reasoning', 'N/A')}

Quick Fix: {finding.get('remediation_summary', 'See detailed plan')}
""".strip()


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def _send_slack(payload: dict) -> None:
    """Post a message to Slack via webhook."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = Request(SLACK_WEBHOOK_URL, data=data, headers={"Content-Type": "application/json"})
        urlopen(req, timeout=10)
        logger.info("Slack notification sent")
    except URLError as exc:
        logger.error("Slack notification failed: %s", exc)


def _send_sns(subject: str, message: str) -> None:
    """Publish to SNS topic."""
    try:
        sns = boto3.client("sns")
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
        logger.info("SNS notification sent")
    except Exception as exc:
        logger.error("SNS notification failed: %s", exc)


def _active_channels() -> list[str]:
    channels = []
    if SLACK_WEBHOOK_URL:
        channels.append("slack")
    if SNS_TOPIC_ARN:
        channels.append("sns")
    return channels


def _score_color(score: int) -> str:
    if score >= 8:
        return "#dc3545"  # Red
    if score >= 5:
        return "#fd7e14"  # Orange
    if score >= 3:
        return "#ffc107"  # Yellow
    return "#28a745"      # Green


def _score_icon(score: int) -> str:
    if score >= 8:
        return "🔴"
    if score >= 5:
        return "🟠"
    if score >= 3:
        return "🟡"
    return "🟢"
