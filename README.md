# AI-Powered Compliance Drift Detector for AWS

> **Turn thousands of noisy security findings into a ranked action plan with one-click fixes — powered by Amazon Bedrock.**

[![CI/CD](https://github.com/niting9881/aws-hackathon-mar2026/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/niting9881/aws-hackathon-mar2026/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![AWS SAM](https://img.shields.io/badge/AWS-SAM-orange.svg)](https://aws.amazon.com/serverless/sam/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## The Problem

Enterprises running multi-account AWS environments face a **compliance visibility crisis**:

- **AWS Security Hub** generates **thousands of findings per week** across accounts — open S3 buckets, overly permissive IAM roles, unencrypted volumes, exposed databases.
- **80% of findings are noise** — low-severity, duplicated, or already resolved. Security teams can't manually triage them all.
- **No contextual prioritization** — Security Hub labels an open S3 bucket as "CRITICAL" whether it holds customer PII or static marketing images. Same severity, wildly different real-world impact.
- **Remediation is slow and manual** — after identifying an issue, engineers spend hours writing fix scripts, getting approvals, and verifying the fix. For common drifts, this is repetitive toil.
- **Root causes are hidden** — 500 individual findings might stem from just 12 underlying issues (a bad CloudFormation template, a misconfigured VPC module). Without clustering, teams fix symptoms instead of causes.

**The result**: Mean Time to Remediation (MTTR) for compliance drifts averages **4+ days** in most organizations. The average cost of a misconfiguration-related breach is **$4.45M** (IBM 2023).

---

## How This Project Solves It

This project uses **Amazon Bedrock (Claude)** as an AI-powered security analyst that sits between your AWS security services and your engineering team:

### 1. Blast Radius Scoring (1-10)
Instead of treating every "CRITICAL" finding equally, the AI evaluates **real-world impact** by considering:
- Resource tags (is this PII data? production? customer-facing?)
- Network exposure (is it publicly accessible? in what VPC?)
- Connected services (what breaks if this is exploited?)
- Historical drift patterns (has this been fixed and reverted 5 times?)

**Result**: A public S3 bucket holding PII scores **9/10**. One holding marketing images scores **2/10**. Your team knows exactly where to focus.

### 2. Root Cause Clustering
The AI groups 500 findings into ~12 actionable root causes:
- "These 47 unencrypted S3 buckets all come from the same CloudFormation template"
- "These 31 security groups are all using the default VPC module"

**Result**: Fix 12 root causes instead of 500 individual findings.

### 3. Contextual Remediation
For each finding, the AI generates the **exact fix** — not generic advice, but runnable AWS CLI commands, CloudFormation snippets, and Terraform blocks specific to your resource configuration.

### 4. Automated Workflow with Human Approval
- Score < 4 → **auto-remediated** (low risk, safe actions)
- Score 4-7 → **triaged and queued** for review
- Score 7+ → **approval workflow triggered** via Slack/SNS, one-click approve, auto-execute

### 5. Drift Prediction
Analyzes historical patterns to flag resources likely to drift again:
- "This security group was tightened 3 times this month but keeps getting reverted by a deployment pipeline"

---

## Technology Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA INGESTION LAYER                         │
│                                                                  │
│  ┌──────────┐  ┌──────────────┐  ┌────────────┐  ┌───────────┐ │
│  │AWS Config │  │Security Hub  │  │IAM Access  │  │CloudTrail │ │
│  │  Rules    │  │  Findings    │  │ Analyzer   │  │  Logs     │ │
│  └────┬─────┘  └──────┬───────┘  └─────┬──────┘  └─────┬─────┘ │
└───────┼───────────────┼────────────────┼───────────────┼────────┘
        │               │                │               │
        ▼               ▼                ▼               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AMAZON EVENTBRIDGE                             │
│                 (Central Event Bus)                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AI ANALYSIS LAYER                              │
│                                                                  │
│  ┌──────────────────────┐      ┌────────────────────────────┐   │
│  │  Lambda + Bedrock     │◄────►│  Bedrock Knowledge Base    │   │
│  │  (Triage & Score)     │      │  (CIS, NIST, Org Policies) │   │
│  └──────────┬───────────┘      └────────────────────────────┘   │
└─────────────┼───────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│               STORAGE & ORCHESTRATION LAYER                      │
│                                                                  │
│  ┌──────────┐    ┌───────────────┐    ┌────────────────┐        │
│  │ DynamoDB  │    │Step Functions  │    │ S3 Remediation │        │
│  │ (State)   │    │ (Workflow)     │    │ (Scripts)      │        │
│  └──────────┘    └───────────────┘    └────────────────┘        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      OUTPUT LAYER                                │
│                                                                  │
│  ┌──────────┐    ┌───────────────┐    ┌────────────────┐        │
│  │QuickSight │    │ SNS + Slack   │    │Auto-Remediation│        │
│  │(Dashboard)│    │ (Alerts)      │    │(With Approval) │        │
│  └──────────┘    └───────────────┘    └────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

---

## High-Level Flow Diagram

```
Security Hub Finding
        │
        ▼
   EventBridge
        │
        ▼
┌───────────────┐
│ Triage Lambda │──── Enrich with resource tags, config, exposure
│               │──── Fetch drift history from DynamoDB
│               │──── Call Bedrock for blast radius scoring (1-10)
│               │──── Generate remediation plan
│               │──── Store enriched finding
└───────┬───────┘
        │
        ▼
  ┌─────────────┐
  │ Score >= 7? │
  └──┬──────┬───┘
     │      │
   Yes      No
     │      │
     ▼      ▼
  ┌──────┐ ┌──────────────┐
  │Start │ │Store & notify│
  │Step  │ │(queued for   │
  │Func. │ │ review)      │
  └──┬───┘ └──────────────┘
     │
     ▼
  ┌──────────────┐
  │ Score < 4?   │
  └──┬───────┬───┘
     │       │
   Yes       No
     │       │
     ▼       ▼
  Auto    ┌──────────────┐
  approve │ Send approval │
     │    │ to Slack/SNS  │
     │    └──────┬───────┘
     │           │
     │     Human approves
     │           │
     ▼           ▼
  ┌──────────────────┐
  │ Execute           │
  │ Remediation       │──── Run AWS SDK calls (block S3, revoke SG rules, etc.)
  │ Lambda            │──── Verify fix applied
  └──────┬───────────┘
         │
         ▼
  ┌──────────────┐
  │ Notify via   │
  │ Slack/SNS    │
  └──────────────┘
```

---

## Technology Stack

| Layer | Service | Purpose |
|-------|---------|---------|
| **AI Engine** | Amazon Bedrock (Claude 3 Sonnet) | Blast radius scoring, remediation generation, root cause clustering, drift prediction |
| **Data Sources** | AWS Config, Security Hub, IAM Access Analyzer, CloudTrail | Compliance findings, configuration changes, API audit logs |
| **Event Routing** | Amazon EventBridge | Real-time event ingestion and filtering |
| **Compute** | AWS Lambda (Python 3.12) | Triage, remediation execution, notifications |
| **Orchestration** | AWS Step Functions | Human-in-the-loop approval workflow with auto-approve for low-risk findings |
| **Storage** | Amazon DynamoDB | Finding state, drift history, remediation tracking |
| **Knowledge Base** | Bedrock Knowledge Bases + S3 | CIS benchmarks, NIST frameworks, org-specific policies (RAG) |
| **Notifications** | Amazon SNS, Slack Webhooks | Alerts, approval requests, remediation results |
| **Dashboard** | Amazon QuickSight / HTML Dashboard | Compliance posture visualization |
| **Infrastructure** | AWS SAM / CloudFormation | Infrastructure as Code |
| **CI/CD** | GitHub Actions | Automated testing, linting, deployment |

---

## Project Structure

```
aws-hackathon-mar2026/
├── src/
│   ├── lambdas/
│   │   ├── triage/            # Main Lambda — parses, enriches, scores, routes
│   │   │   └── handler.py
│   │   ├── remediation/       # Executes approved remediation actions
│   │   │   └── handler.py
│   │   └── notifier/          # Slack and SNS notification formatting
│   │       └── handler.py
│   ├── bedrock/
│   │   ├── __init__.py
│   │   └── analyzer.py        # Bedrock AI integration (scoring, remediation, clustering)
│   ├── step_functions/
│   │   └── remediation_workflow.json   # State machine definition
│   └── utils/
│       ├── aws_helpers.py     # Resource enrichment, DynamoDB, SNS helpers
│       └── finding_parser.py  # ASFF finding parser and categorizer
├── infrastructure/
│   └── cfn/
│       └── template.yaml      # SAM/CloudFormation template (full stack)
├── config/
│   └── settings.json          # Project configuration
├── tests/
│   └── test_triage.py         # 31 unit tests
├── sample_events/
│   ├── s3_public_access.json       # Sample: public S3 bucket with PII
│   ├── security_group_open.json    # Sample: open MySQL + SSH security group
│   └── iam_overpermissive.json     # Sample: IAM role with admin access
├── scripts/
│   ├── local_test.py          # Local pipeline simulation (no AWS needed)
│   └── deploy.sh              # One-command deployment script
├── dashboard/
│   └── index.html             # Interactive compliance dashboard
├── .github/
│   └── workflows/
│       └── ci-cd.yml          # GitHub Actions CI/CD pipeline
├── requirements.txt
├── .gitignore
└── README.md
```

---

## How to Run the Program

### Prerequisites

- **Python 3.11+**
- **AWS CLI v2** configured with credentials
- **AWS SAM CLI** (for deployment)
- **AWS Account** with Security Hub and Bedrock enabled
- **Bedrock Model Access**: Request access to Claude 3 Sonnet in the [Bedrock console](https://console.aws.amazon.com/bedrock/)

### Option 1: Local Simulation (No AWS Required)

This runs the full pipeline locally with simulated AI responses — perfect for understanding the flow without any AWS costs.

```bash
# Clone the repository
git clone https://github.com/niting9881/aws-hackathon-mar2026.git
cd aws-hackathon-mar2026

# Install dependencies
pip install -r requirements.txt

# Run simulation on all sample findings
python scripts/local_test.py

# Run on a specific finding
python scripts/local_test.py --event sample_events/s3_public_access.json
python scripts/local_test.py --event sample_events/security_group_open.json
python scripts/local_test.py --event sample_events/iam_overpermissive.json
```

**Expected output**: A step-by-step walkthrough showing parsing → enrichment → AI scoring → remediation → workflow decision for each finding.

### Option 2: Run Unit Tests

```bash
# Run all 31 tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=src --cov-report=term-missing
```

### Option 3: Deploy to AWS

```bash
# Make the deployment script executable
chmod +x scripts/deploy.sh

# Deploy to dev environment
./scripts/deploy.sh dev us-east-1

# Deploy to production
./scripts/deploy.sh prod us-east-1
```

**What the deployment script does:**
1. Validates AWS credentials and Bedrock model access
2. Runs the full test suite
3. Builds and packages Lambda functions with SAM
4. Deploys the CloudFormation stack (DynamoDB, Lambda, Step Functions, EventBridge rules, SNS, IAM roles)
5. Prints the stack outputs (ARNs, table names, dashboard URL)

### Option 4: Manual SAM Deployment

```bash
# Build
sam build --template infrastructure/cfn/template.yaml

# Deploy (interactive guided mode)
sam deploy --guided --capabilities CAPABILITY_NAMED_IAM

# You'll be prompted for:
#   Stack name: compliance-drift-detector-dev
#   Region: us-east-1
#   Environment: dev
#   BlastRadiusThreshold: 7
#   SlackWebhookUrl: (optional)
#   NotificationEmail: your@email.com
```

### Option 5: View the Dashboard

```bash
# Open the dashboard locally
open dashboard/index.html
# or
python -m http.server 8080 -d dashboard/
# Then visit http://localhost:8080
```

---

## Post-Deployment Setup

### 1. Enable Security Hub (if not already)
```bash
aws securityhub enable-security-hub --enable-default-standards
```

### 2. Enable AWS Config
```bash
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT:role/config-role \
  --recording-group allSupported=true
```

### 3. (Optional) Configure Slack notifications
Set the `SLACK_WEBHOOK_URL` environment variable on the Notifier Lambda, or pass it as a parameter during deployment.

### 4. Test with a sample finding
```bash
# Invoke the triage Lambda directly with a sample event
aws lambda invoke \
  --function-name compliance-triage-dev \
  --payload file://sample_events/s3_public_access.json \
  --cli-binary-format raw-in-base64-out \
  output.json

cat output.json
```

---

## Configuration

All configuration is in `config/settings.json`:

| Setting | Default | Description |
|---------|---------|-------------|
| `bedrock.model_id` | `anthropic.claude-3-sonnet-20240229-v1:0` | Bedrock model for AI analysis |
| `scoring.blast_radius_threshold` | `7` | Score at which remediation workflow auto-starts |
| `scoring.auto_approve_below` | `3` | Score below which fixes are auto-applied |
| `remediation.approval_timeout_hours` | `24` | Hours before an unapproved fix times out |
| `notifications.severity_filter` | `MEDIUM` | Minimum Security Hub severity to process |
| `dynamodb.ttl_days` | `90` | Auto-delete resolved findings after N days |

---

## FAQ

### Q: Does this actually call AWS Bedrock in the local simulation?
**No.** The `local_test.py` script uses hardcoded mock responses that simulate what Bedrock would return. This lets you see the full pipeline flow without any AWS costs. Real Bedrock calls only happen when deployed to AWS.

### Q: Which AWS regions support this?
Any region that supports both **Security Hub** and **Amazon Bedrock** with Claude models. As of 2026, this includes `us-east-1`, `us-west-2`, `eu-west-1`, and `ap-northeast-1`. Check the [Bedrock region table](https://docs.aws.amazon.com/general/latest/gr/bedrock.html) for the latest.

### Q: How much does this cost to run?
For a typical mid-size org (20 accounts, ~500 findings/week):
- **Bedrock (Claude 3 Sonnet)**: ~$5-15/month (scoring + remediation for each finding)
- **Lambda**: ~$2-5/month (included in free tier for most)
- **DynamoDB**: ~$1-3/month (on-demand pricing)
- **Step Functions**: ~$1/month
- **Total**: Roughly **$10-25/month** — compared to $50K+/year for commercial CSPM tools

### Q: Will the auto-remediation break anything?
The system has multiple safety layers:
1. Only **pre-approved safe actions** are auto-executed (blocking S3 public access, revoking open security group rules)
2. **Destructive actions** (like detaching IAM policies) are always **skipped** and flagged for manual execution
3. Score 5+ findings **always require human approval** via Slack/SNS before any action is taken
4. Every remediation includes **rollback commands** in case something goes wrong
5. All actions are logged in DynamoDB with full audit trail

### Q: Can I customize the blast radius scoring criteria?
Yes. The scoring prompt is in `src/bedrock/analyzer.py` under `BLAST_RADIUS_PROMPT`. You can modify the scoring criteria, add your organization's specific risk factors, or weight certain data classifications higher.

### Q: How does this differ from AWS Security Hub's built-in severity?
Security Hub assigns severity based on the **type** of misconfiguration. This tool adds **context-aware** scoring based on:
- What data the resource actually holds (from tags)
- Whether it's in production or dev
- How exposed it is to the internet
- How many other services depend on it
- Historical drift patterns

A "CRITICAL" public S3 bucket holding test data scores 2/10. A "HIGH" security group protecting a production database with PII scores 9/10.

### Q: Can this work with GovCloud or China regions?
The architecture is region-agnostic, but you'll need to verify Bedrock model availability in GovCloud. The CloudFormation template uses `!Ref AWS::Region` throughout, so it deploys cleanly to any supported region.

### Q: How do I add support for new resource types?
1. Add an enrichment function in `src/utils/aws_helpers.py` (e.g., `_enrich_lambda()`)
2. Add a remediation handler in `src/lambdas/remediation/handler.py`
3. Add the action to `SAFE_ACTIONS` if it's non-destructive
4. The AI scoring and remediation generation work automatically for any resource type — they read the finding description and resource context

### Q: What compliance frameworks does this support?
Out of the box: **CIS AWS Foundations**, **AWS Foundational Security Best Practices**, **NIST 800-53**, **PCI DSS**, **HIPAA**, and **SOC 2**. The framework is auto-detected from the Security Hub finding's GeneratorId. You can add custom frameworks by updating the knowledge base.

### Q: Can I use a different AI model?
Yes. Change the `BEDROCK_MODEL_ID` environment variable. The prompts are written for Claude but work with any Bedrock model that supports JSON output. Tested with Claude 3 Sonnet, Claude 3 Haiku (faster, cheaper), and Claude 3.5 Sonnet (most accurate).

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Run the tests (`python -m pytest tests/ -v`)
4. Commit your changes (`git commit -am 'Add new feature'`)
5. Push to the branch (`git push origin feature/my-feature`)
6. Open a Pull Request

---


**Built for the AWS Hackathon March 2026** | Uses Amazon Bedrock, Security Hub, Lambda, Step Functions, DynamoDB, EventBridge, and SNS
