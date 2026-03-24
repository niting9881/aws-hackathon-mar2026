"""
Unit tests for the AI Compliance Drift Detector.

Tests cover:
  - ASFF finding parsing
  - Finding categorization
  - Blast radius prompt construction
  - Remediation plan structure
  - DynamoDB item serialization
"""

import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.utils.finding_parser import (
    parse_security_hub_finding,
    get_finding_category,
    _extract_resource_id,
    _extract_framework,
    _build_dedup_key,
)
from src.utils.aws_helpers import _to_dynamodb_item, _from_dynamodb_item


class TestFindingParser(unittest.TestCase):
    """Test ASFF finding parsing."""

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "sample_events", "s3_public_access.json")) as f:
            self.s3_event = json.load(f)

        with open(os.path.join(os.path.dirname(__file__), "..", "sample_events", "security_group_open.json")) as f:
            self.sg_event = json.load(f)

        with open(os.path.join(os.path.dirname(__file__), "..", "sample_events", "iam_overpermissive.json")) as f:
            self.iam_event = json.load(f)

    def test_parse_s3_finding(self):
        result = parse_security_hub_finding(self.s3_event)
        self.assertEqual(result["count"], 1)

        finding = result["findings"][0]
        self.assertEqual(finding["resource_type"], "AwsS3Bucket")
        self.assertEqual(finding["severity_label"], "CRITICAL")
        self.assertEqual(finding["severity_normalized"], 90)
        self.assertEqual(finding["compliance_status"], "FAILED")
        self.assertIn("S3", finding["title"])
        self.assertEqual(finding["account_id"], "123456789012")

    def test_parse_sg_finding(self):
        result = parse_security_hub_finding(self.sg_event)
        finding = result["findings"][0]
        self.assertEqual(finding["resource_type"], "AwsEc2SecurityGroup")
        self.assertEqual(finding["severity_label"], "HIGH")

    def test_parse_iam_finding(self):
        result = parse_security_hub_finding(self.iam_event)
        finding = result["findings"][0]
        self.assertEqual(finding["resource_type"], "AwsIamRole")
        self.assertIn("legacy-deployment-role", finding["resource_id"])

    def test_parse_direct_finding(self):
        """Test parsing a raw ASFF finding (not wrapped in EventBridge)."""
        raw = self.s3_event["detail"]["findings"][0]
        result = parse_security_hub_finding(raw)
        self.assertEqual(result["count"], 1)

    def test_invalid_event_raises(self):
        with self.assertRaises(ValueError):
            parse_security_hub_finding({"foo": "bar"})

    def test_dedup_key_is_stable(self):
        key1 = _build_dedup_key("gen1", "arn:aws:s3:::bucket", "title")
        key2 = _build_dedup_key("gen1", "arn:aws:s3:::bucket", "title")
        self.assertEqual(key1, key2)

    def test_dedup_key_varies(self):
        key1 = _build_dedup_key("gen1", "arn:aws:s3:::bucket-a", "title")
        key2 = _build_dedup_key("gen1", "arn:aws:s3:::bucket-b", "title")
        self.assertNotEqual(key1, key2)


class TestFindingCategorization(unittest.TestCase):
    """Test finding category classification."""

    def test_encryption_category(self):
        finding = {"title": "S3 bucket does not have encryption enabled", "resource_type": "AwsS3Bucket"}
        self.assertEqual(get_finding_category(finding), "encryption")

    def test_public_access_category(self):
        finding = {"title": "S3 bucket has public read access", "resource_type": "AwsS3Bucket"}
        self.assertEqual(get_finding_category(finding), "public_access")

    def test_iam_category(self):
        finding = {"title": "IAM policy allows full admin privileges", "resource_type": "AwsIamRole"}
        self.assertEqual(get_finding_category(finding), "iam_permissions")

    def test_networking_category(self):
        finding = {"title": "Security group has overly broad ingress rules", "resource_type": "AwsEc2SecurityGroup"}
        self.assertEqual(get_finding_category(finding), "networking")

    def test_fallback_by_resource_type(self):
        finding = {"title": "Something unusual", "resource_type": "AwsIamRole"}
        self.assertEqual(get_finding_category(finding), "iam_permissions")

    def test_general_fallback(self):
        finding = {"title": "Something unexpected", "resource_type": "AwsOther"}
        self.assertEqual(get_finding_category(finding), "general")


class TestResourceIdExtraction(unittest.TestCase):
    """Test ARN parsing."""

    def test_s3_arn(self):
        arn = "arn:aws:s3:::my-bucket-name"
        self.assertEqual(_extract_resource_id(arn, "AwsS3Bucket"), "my-bucket-name")

    def test_iam_role_arn(self):
        arn = "arn:aws:iam::123456789012:role/my-role"
        self.assertEqual(_extract_resource_id(arn, "AwsIamRole"), "my-role")

    def test_sg_arn(self):
        arn = "arn:aws:ec2:us-east-1:123456789012:security-group/sg-abc123"
        self.assertEqual(_extract_resource_id(arn, "AwsEc2SecurityGroup"), "sg-abc123")

    def test_non_arn(self):
        self.assertEqual(_extract_resource_id("sg-abc123", "AwsEc2SecurityGroup"), "sg-abc123")


class TestFrameworkExtraction(unittest.TestCase):
    """Test compliance framework detection."""

    def test_cis(self):
        finding = {"GeneratorId": "cis-aws-foundations-benchmark/v/1.4.0/2.1.5"}
        self.assertEqual(_extract_framework(finding), "CIS AWS Foundations")

    def test_nist(self):
        finding = {"GeneratorId": "nist-800-53/AC-6"}
        self.assertEqual(_extract_framework(finding), "NIST 800-53")

    def test_aws_foundational(self):
        finding = {"GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.2"}
        self.assertEqual(_extract_framework(finding), "AWS Foundational Security Best Practices")

    def test_unknown(self):
        finding = {"GeneratorId": "custom-rule-123"}
        self.assertEqual(_extract_framework(finding), "General")


class TestDynamoDBSerialization(unittest.TestCase):
    """Test DynamoDB item conversion."""

    def test_roundtrip(self):
        original = {
            "resource_id": "my-bucket",
            "blast_radius_score": 8,
            "is_critical": True,
            "description": "Public access enabled",
        }
        dynamo_item = _to_dynamodb_item(original)
        restored = _from_dynamodb_item(dynamo_item)

        self.assertEqual(restored["resource_id"], "my-bucket")
        self.assertEqual(restored["blast_radius_score"], 8)
        self.assertEqual(restored["is_critical"], True)
        self.assertEqual(restored["description"], "Public access enabled")

    def test_none_handling(self):
        item = _to_dynamodb_item({"key": None})
        self.assertIn("NULL", item["key"])

    def test_list_serialized_as_json(self):
        item = _to_dynamodb_item({"tags": ["a", "b", "c"]})
        self.assertEqual(item["tags"]["S"], '["a", "b", "c"]')


class TestBedrockPrompts(unittest.TestCase):
    """Test that Bedrock prompt templates are well-formed."""

    def test_blast_radius_prompt_renders(self):
        from src.bedrock.analyzer import BLAST_RADIUS_PROMPT

        rendered = BLAST_RADIUS_PROMPT.format(
            finding_json='{"title": "test"}',
            context_json='{"bucket": "test-bucket"}',
            history_json="[]",
        )
        self.assertIn("test-bucket", rendered)
        self.assertIn("blast radius score", rendered.lower())
        self.assertIn("1 to 10", rendered)

    def test_remediation_prompt_renders(self):
        from src.bedrock.analyzer import REMEDIATION_PROMPT

        rendered = REMEDIATION_PROMPT.format(
            finding_json='{"title": "test"}',
            context_json='{"bucket": "test-bucket"}',
        )
        self.assertIn("remediation", rendered.lower())
        self.assertIn("aws_cli", rendered)

    def test_clustering_prompt_renders(self):
        from src.bedrock.analyzer import CLUSTERING_PROMPT

        rendered = CLUSTERING_PROMPT.format(
            count=5,
            findings_json='[{"id": "1"}, {"id": "2"}]',
        )
        self.assertIn("5", rendered)
        self.assertIn("root cause", rendered.lower())


class TestJsonParsing(unittest.TestCase):
    """Test the JSON extraction from model responses."""

    def test_clean_json(self):
        from src.bedrock.analyzer import _parse_json_response

        text = '{"blast_radius_score": 7, "confidence": 0.85}'
        result = _parse_json_response(text)
        self.assertEqual(result["blast_radius_score"], 7)

    def test_json_in_code_fences(self):
        from src.bedrock.analyzer import _parse_json_response

        text = '```json\n{"blast_radius_score": 9}\n```'
        result = _parse_json_response(text)
        self.assertEqual(result["blast_radius_score"], 9)

    def test_json_with_preamble(self):
        from src.bedrock.analyzer import _parse_json_response

        text = 'Here is the analysis:\n\n{"blast_radius_score": 4}'
        result = _parse_json_response(text)
        self.assertEqual(result["blast_radius_score"], 4)

    def test_invalid_json_returns_default(self):
        from src.bedrock.analyzer import _parse_json_response

        text = "This is not JSON at all."
        result = _parse_json_response(text, default={"score": 0})
        self.assertEqual(result["score"], 0)


if __name__ == "__main__":
    unittest.main()
