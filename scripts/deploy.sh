#!/bin/bash
# ==========================================================================
#  AI Compliance Drift Detector — Deployment Script
# ==========================================================================
#
#  Usage:
#    ./scripts/deploy.sh [environment] [region]
#
#  Examples:
#    ./scripts/deploy.sh dev us-east-1
#    ./scripts/deploy.sh prod us-west-2
#
# ==========================================================================

set -euo pipefail

ENVIRONMENT="${1:-dev}"
REGION="${2:-us-east-1}"
STACK_NAME="compliance-drift-detector-${ENVIRONMENT}"
TEMPLATE="infrastructure/cfn/template.yaml"
S3_BUCKET="compliance-drift-deploy-${ENVIRONMENT}-$(aws sts get-caller-identity --query Account --output text)"

echo "============================================================"
echo "  Deploying AI Compliance Drift Detector"
echo "  Environment: ${ENVIRONMENT}"
echo "  Region:      ${REGION}"
echo "  Stack:       ${STACK_NAME}"
echo "============================================================"
echo ""

# Check prerequisites
echo "Checking prerequisites..."
command -v aws >/dev/null 2>&1 || { echo "AWS CLI required. Install: https://aws.amazon.com/cli/"; exit 1; }
command -v sam >/dev/null 2>&1 || { echo "AWS SAM CLI required. Install: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html"; exit 1; }

# Verify AWS credentials
aws sts get-caller-identity > /dev/null 2>&1 || { echo "AWS credentials not configured. Run: aws configure"; exit 1; }
echo "  ✓ AWS credentials valid"

# Check Bedrock model access
echo "  Checking Bedrock model access..."
aws bedrock list-foundation-models --region "${REGION}" --query "modelSummaries[?modelId=='anthropic.claude-3-sonnet-20240229-v1:0'].modelId" --output text > /dev/null 2>&1 || {
    echo "  ⚠ Warning: Could not verify Bedrock model access."
    echo "    Ensure you have requested access to Claude 3 Sonnet in the Bedrock console."
}

# Create S3 bucket for deployment artifacts if needed
echo ""
echo "Creating deployment bucket (if needed)..."
aws s3 mb "s3://${S3_BUCKET}" --region "${REGION}" 2>/dev/null || true
echo "  ✓ Bucket: ${S3_BUCKET}"

# Run tests first
echo ""
echo "Running unit tests..."
python -m pytest tests/ -v --tb=short || {
    echo "  ✗ Tests failed. Fix issues before deploying."
    exit 1
}
echo "  ✓ All tests passed"

# Build and package
echo ""
echo "Building and packaging..."
sam build \
    --template-file "${TEMPLATE}" \
    --build-dir .aws-sam/build \
    --region "${REGION}"

sam package \
    --template-file .aws-sam/build/template.yaml \
    --output-template-file .aws-sam/packaged.yaml \
    --s3-bucket "${S3_BUCKET}" \
    --region "${REGION}"

echo "  ✓ Package uploaded to S3"

# Deploy
echo ""
echo "Deploying stack..."
sam deploy \
    --template-file .aws-sam/packaged.yaml \
    --stack-name "${STACK_NAME}" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --region "${REGION}" \
    --parameter-overrides \
        "Environment=${ENVIRONMENT}" \
        "BedrockModelId=anthropic.claude-3-sonnet-20240229-v1:0" \
        "BlastRadiusThreshold=7" \
    --no-confirm-changeset \
    --no-fail-on-empty-changeset

echo ""
echo "============================================================"
echo "  Deployment complete!"
echo "============================================================"
echo ""

# Show outputs
aws cloudformation describe-stacks \
    --stack-name "${STACK_NAME}" \
    --region "${REGION}" \
    --query "Stacks[0].Outputs" \
    --output table

echo ""
echo "Next steps:"
echo "  1. Enable Security Hub in your account (if not already)"
echo "  2. Enable AWS Config rules for compliance checks"
echo "  3. (Optional) Configure Slack webhook in parameter store"
echo "  4. (Optional) Set up QuickSight dashboard"
echo ""
