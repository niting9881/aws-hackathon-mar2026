"""
Amazon Bedrock integration for AI-powered compliance analysis.

This module handles:
  1. Blast radius scoring — prioritize findings by real-world impact
  2. Remediation generation — produce runnable fix scripts
  3. Root cause clustering — group related findings
  4. Drift prediction — flag resources likely to re-drift
"""

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", "us-east-1")

_bedrock_client = None


def _get_bedrock():
    global _bedrock_client
    if _bedrock_client is None:
        _bedrock_client = boto3.client(
            "bedrock-runtime", region_name=BEDROCK_REGION
        )
    return _bedrock_client


# ---------------------------------------------------------------------------
# 1. Blast radius scoring
# ---------------------------------------------------------------------------

BLAST_RADIUS_PROMPT = """You are an expert AWS security analyst. Analyze the following compliance finding and its resource context to determine a **blast radius score** from 1 to 10.

**Scoring criteria:**
- **1-3 (Low):** Non-production resource, no sensitive data, limited network exposure, internal-only access
- **4-6 (Medium):** Production resource with some exposure, business data at risk, moderate blast radius
- **7-9 (High):** Production resource with PII/financial data, public exposure, cross-account impact, directly exploitable
- **10 (Critical):** Active exploitation likely, massive data exposure, regulatory violation imminent

**Finding:**
```json
{finding_json}
```

**Resource context (tags, configuration, exposure):**
```json
{context_json}
```

**Historical drift data (how often this resource has drifted before):**
```json
{history_json}
```

Respond ONLY with a JSON object in this exact format:
{{
  "blast_radius_score": <integer 1-10>,
  "confidence": <float 0.0-1.0>,
  "reasoning": "<2-3 sentence explanation>",
  "risk_factors": ["<factor1>", "<factor2>", ...],
  "affected_services": ["<service1>", "<service2>", ...],
  "data_sensitivity": "<none|internal|confidential|pii|financial|regulated>",
  "exploitability": "<none|theoretical|possible|likely|active>"
}}"""


def score_blast_radius(
    finding: dict,
    resource_context: dict,
    drift_history: list[dict] | None = None,
) -> dict:
    """
    Use Bedrock to score the blast radius of a compliance finding.

    Returns a dict with blast_radius_score, confidence, reasoning, etc.
    """
    prompt = BLAST_RADIUS_PROMPT.format(
        finding_json=json.dumps(finding, indent=2, default=str),
        context_json=json.dumps(resource_context, indent=2, default=str),
        history_json=json.dumps(drift_history or [], indent=2, default=str),
    )

    response = _invoke_model(prompt)
    return _parse_json_response(response, default={"blast_radius_score": 5})


# ---------------------------------------------------------------------------
# 2. Remediation generation
# ---------------------------------------------------------------------------

REMEDIATION_PROMPT = """You are an AWS security engineer. Generate a remediation plan for the following compliance finding.

**Finding:**
```json
{finding_json}
```

**Resource context:**
```json
{context_json}
```

Generate:
1. A clear explanation of the issue
2. The exact AWS CLI commands to fix it
3. An equivalent CloudFormation / Terraform snippet
4. Any rollback steps if the fix causes issues
5. Validation steps to confirm the fix worked

Respond ONLY with a JSON object in this exact format:
{{
  "issue_summary": "<1-2 sentence plain-English explanation>",
  "risk_if_unfixed": "<what could happen if this is not fixed>",
  "remediation_steps": [
    {{
      "step_number": 1,
      "description": "<what this step does>",
      "aws_cli": "<exact CLI command>",
      "is_destructive": <true|false>
    }}
  ],
  "cloudformation_snippet": "<CloudFormation YAML snippet>",
  "terraform_snippet": "<Terraform HCL snippet>",
  "rollback_steps": ["<step1>", "<step2>"],
  "validation_commands": ["<aws cli command to verify fix>"],
  "estimated_fix_time_minutes": <integer>,
  "requires_downtime": <true|false>
}}"""


def generate_remediation(finding: dict, resource_context: dict) -> dict:
    """
    Generate contextual remediation scripts for a specific finding.
    """
    prompt = REMEDIATION_PROMPT.format(
        finding_json=json.dumps(finding, indent=2, default=str),
        context_json=json.dumps(resource_context, indent=2, default=str),
    )

    response = _invoke_model(prompt, max_tokens=4096)
    return _parse_json_response(response, default={"issue_summary": "Unable to generate remediation"})


# ---------------------------------------------------------------------------
# 3. Root cause clustering
# ---------------------------------------------------------------------------

CLUSTERING_PROMPT = """You are an AWS security architect. Analyze these {count} compliance findings and group them by root cause.

Many findings are symptoms of the same underlying issue (e.g., 50 unencrypted S3 buckets might all stem from a CloudFormation template missing an encryption property).

**Findings:**
```json
{findings_json}
```

Group these into root cause clusters. For each cluster, identify:
- The root cause
- Which findings belong to it
- A single fix that resolves all findings in the cluster

Respond ONLY with a JSON object:
{{
  "clusters": [
    {{
      "cluster_id": "<short-id>",
      "root_cause": "<description of the underlying issue>",
      "finding_ids": ["<id1>", "<id2>", ...],
      "finding_count": <integer>,
      "single_fix": "<one action that fixes all findings in this cluster>",
      "priority": "<critical|high|medium|low>",
      "estimated_effort_hours": <number>
    }}
  ],
  "total_clusters": <integer>,
  "reduction_ratio": "<e.g., 500 findings → 12 root causes>"
}}"""


def cluster_findings(findings: list[dict]) -> dict:
    """
    Group a batch of findings by root cause to reduce noise.
    """
    prompt = CLUSTERING_PROMPT.format(
        count=len(findings),
        findings_json=json.dumps(findings, indent=2, default=str),
    )

    response = _invoke_model(prompt, max_tokens=4096)
    return _parse_json_response(response, default={"clusters": [], "total_clusters": 0})


# ---------------------------------------------------------------------------
# 4. Drift prediction
# ---------------------------------------------------------------------------

DRIFT_PREDICTION_PROMPT = """You are an AWS compliance analyst. Based on the drift history for this resource, predict whether it will drift again and identify the likely cause.

**Resource:** {resource_id} ({resource_type})
**Account:** {account_id}
**Region:** {region}

**Drift history (last 90 days):**
```json
{history_json}
```

Analyze patterns: Does this resource keep drifting? Is it on a schedule (e.g., every deployment)? Is someone manually reverting security controls?

Respond ONLY with a JSON object:
{{
  "will_drift_again": <true|false>,
  "confidence": <float 0.0-1.0>,
  "predicted_cause": "<likely reason for repeated drift>",
  "pattern_detected": "<e.g., 'drifts every Tuesday after deployment pipeline runs'>",
  "recommendation": "<how to permanently fix the root cause>",
  "days_until_likely_drift": <integer or null>
}}"""


def predict_drift(
    resource_id: str,
    resource_type: str,
    account_id: str,
    region: str,
    drift_history: list[dict],
) -> dict:
    """
    Predict whether a resource will drift again based on historical patterns.
    """
    prompt = DRIFT_PREDICTION_PROMPT.format(
        resource_id=resource_id,
        resource_type=resource_type,
        account_id=account_id,
        region=region,
        history_json=json.dumps(drift_history, indent=2, default=str),
    )

    response = _invoke_model(prompt)
    return _parse_json_response(response, default={"will_drift_again": False})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _invoke_model(prompt: str, max_tokens: int = 2048) -> str:
    """Call Bedrock's Converse / InvokeModel API and return the text response."""
    client = _get_bedrock()

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "temperature": 0.1,
        "messages": [{"role": "user", "content": prompt}],
    })

    try:
        resp = client.invoke_model(
            modelId=MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=body,
        )
        result = json.loads(resp["body"].read())
        return result["content"][0]["text"]

    except ClientError as exc:
        logger.error("Bedrock invocation failed: %s", exc)
        raise
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        logger.error("Failed to parse Bedrock response: %s", exc)
        raise


def _parse_json_response(text: str, default: dict | None = None) -> dict:
    """
    Extract and parse JSON from the model's response.
    Handles cases where the model wraps JSON in markdown code fences.
    """
    cleaned = text.strip()

    # Strip markdown code fences if present
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        # Remove first and last line (the fences)
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to find JSON object within the text
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(cleaned[start:end])
            except json.JSONDecodeError:
                pass

        logger.warning("Could not parse JSON from model response, using default")
        return default or {}
