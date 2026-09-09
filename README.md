# Operationalizing Least Privilege: Automating IAM Permission Remediation Through Infrastructure Context

> **Note:** This is a sample solution for educational purposes. Any applications you integrate these examples into should be thoroughly tested, secured, and optimized according to your organization's security standards and policies before deploying to production.

Automated AWS Identity and Access Management (AWS IAM) permission remediation using AWS Identity and Access Management Access Analyzer, AWS CloudTrail, AWS Lambda, and Amazon Bedrock for intelligent AWS Cloud Development Kit (AWS CDK) code generation.

## Overview

This solution automates the remediation of unused IAM permissions by:

1. **Detecting** unused permissions via AWS Identity and Access Management Access Analyzer (IAM Access Analyzer)
2. **Attributing** roles to their origin (IaC vs manual) using AWS CloudTrail
3. **Generating** production-ready AWS Cloud Development Kit (AWS CDK) code using Amazon Bedrock
4. **Creating** pull requests or issues in your CI/CD system

## Features

- ✅ Dual-path remediation (IaC roles → PRs, manual roles → issues)
- ✅ AI-generated AWS Cloud Development Kit (AWS CDK) code using Amazon Bedrock
- ✅ Policy diff generation for human review
- ✅ CloudTrail-based role attribution
- ✅ GitLab and GitHub integration
- ✅ Configurable exclusion rules
- ✅ Comprehensive logging and metrics

## Architecture

```
IAM Access Analyzer
        ↓
   EventBridge (Daily)
        ↓
   Lambda: Process Findings
        ↓
   CloudTrail Query (Role Attribution)
        ↓
   ┌─────────────────────────────────┐
   ↓                                 ↓
IaC-Managed Roles          Manually-Created Roles
   ↓                                 ↓
Amazon Bedrock CDK Gen     Create Issue with:
Create PR with:            - Updated IAM policy
- Generated CDK code       - Policy diff
- IAM policy diff          - Import guidance
- Context
```

## Prerequisites

- AWS Account with appropriate permissions
- Python 3.9+
- AWS CDK CLI
- GitLab or GitHub account with API token
- AWS IAM Access Analyzer enabled
- Amazon Bedrock model access enabled for the Anthropic Claude models you intend to use (see [Amazon Bedrock model selection](#amazon-bedrock-model-selection) below)

## Quick Start

### 1. Clone Repository

```bash
git clone <repository-url>
cd sample-operationalizing-least-privilege-iam-remediation
```

### 2. Install Dependencies

```bash
# Infrastructure dependencies (CDK)
pip install -r infrastructure/requirements.txt

# Lambda dependencies (bundled into the Lambda deployment package)
./scripts/build_lambda.sh
```

The build script installs Python packages directly into the `lambda/process_findings/` directory so CDK can bundle them into the Lambda deployment asset. This is required before deploying.

### 3. Copy Configuration Templates

```bash
cp config/exclusions.json.example config/exclusions.json
```

```bash
cp config/ci_cd_config.json.example config/ci_cd_config.json
```

### 4. Edit Configuration Files

```bash
vim config/exclusions.json
```

```bash
vim config/ci_cd_config.json
```

### 5. Store Your CI/CD API Token in AWS Secrets Manager

The Lambda function reads the CI/CD API token from AWS Secrets Manager. Do not store the token in environment variables or commit it to source control.

```bash
aws secretsmanager create-secret \
  --name iam-remediation/gitlab-token \
  --secret-string "<your-gitlab-personal-access-token>"
```

### 6. Deploy Infrastructure

```bash
cd infrastructure
cdk deploy
```

## Configuration

The solution uses two configuration files to control its behavior: exclusion rules and CI/CD integration settings. The Amazon Bedrock models are selected separately through Lambda environment variables (see below).

### Amazon Bedrock model selection

The Lambda calls Amazon Bedrock for AWS CDK code generation and for plain-English explanations of policy changes. The model IDs are Lambda environment variables, set in `infrastructure/stacks/remediation_stack.py`, so you can change them without editing the Lambda code:

- `BEDROCK_CODEGEN_MODEL` - model used to generate CDK code (defaults to a current Anthropic Claude model on Amazon Bedrock)
- `BEDROCK_EXPLANATION_MODEL` - model used to generate explanations (defaults to a current Anthropic Claude model on Amazon Bedrock)

> **Note:** Amazon Bedrock periodically retires older foundation models. AWS marks them as legacy and eventually stops accepting new invocations for them. When that happens to the defaults shipped with this solution, the Amazon Bedrock calls will start failing. The run still completes (the Lambda falls back to a generic explanation and skips code generation), but you will not get AI-generated CDK code or explanations until you point the solution at a current model. To fix it: set `BEDROCK_CODEGEN_MODEL` and `BEDROCK_EXPLANATION_MODEL` to current model IDs (or cross-region inference profile IDs) that you have enabled, then redeploy with `cdk deploy --all`. Verify model access on the Amazon Bedrock console "Model access" page and confirm the model is available in your Region.

### Exclusions (config/exclusions.json)

```json
{
  "excluded_roles": [
    "arn:aws:iam::ACCOUNT:role/BreakGlassRole"
  ],
  "excluded_permissions": [
    "iam:*"
  ],
  "excluded_by_tag": {
    "NoRemediation": ["true"]
  },
  "min_unused_days": 30
}
```

### CI/CD Integration (config/ci_cd_config.json)

```json
{
  "platform": "gitlab",
  "api_token_secret": "iam-remediation/gitlab-token",
  "base_url": "https://gitlab.com",
  "iac_repository": "org/iac-repo",
  "issue_labels": ["security", "iam-remediation"],
  "approval_required": true
}
```

## Project Structure

```
iam-permission-remediation-solution/
├── infrastructure/
│   ├── app.py                          # CDK app entry point
│   ├── stacks/
│   │   ├── iam_stack.py                # IAM roles and policies
│   │   └── remediation_stack.py        # Lambda and EventBridge
│   └── requirements.txt
├── lambda/
│   └── process_findings/
│       ├── index.py                    # Main handler
│       ├── analyzer.py                 # Access Analyzer integration
│       ├── cloudtrail.py               # CloudTrail queries
│       ├── remediation.py              # Remediation logic
│       ├── bedrock_codegen.py          # Amazon Bedrock code generation
│       ├── ci_cd_integrations/
│       │   ├── gitlab.py               # GitLab integration
│       │   ├── github.py               # GitHub integration
│       │   └── dryrun.py               # Dry-run mode (no CI/CD)
│       └── requirements.txt
├── scripts/
│   └── build_lambda.sh                 # Install Lambda deps for packaging
├── config/
│   ├── exclusions.json.example         # Exclusion rules template
│   └── ci_cd_config.json.example       # CI/CD settings template
├── LICENSE
└── README.md
```

## Deployment

### Using CDK

```bash
cd infrastructure

# Synthesize CloudFormation template
cdk synth

# Deploy to AWS
cdk deploy

# Destroy resources (when done)
cdk destroy
```

### Manual Deployment

1. Create Lambda function with code from `lambda/process_findings/`
2. Create IAM role with permissions from `infrastructure/stacks/iam_stack.py`
3. Create EventBridge rule to trigger daily
4. Store CI/CD token in AWS Secrets Manager

## Usage

### Trigger Manually

```bash
aws lambda invoke \
  --function-name ProcessFindingsFunction \
  --payload '{}' \
  response.json
```

### View Logs

```bash
aws logs tail /aws/lambda/ProcessFindingsFunction --follow
```

### Monitor Metrics

```bash
aws cloudwatch get-metric-statistics \
  --namespace IAMRemediation \
  --metric-name FindingsProcessed \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Sum
```

## Security Considerations

This solution is provided as sample code for educational purposes and as a reference implementation. Before deploying to production:

- Test in a lower environment first (development or staging account) using test resources with non-production data. Validate behavior, IAM permissions, and notification thresholds before promoting to production.
- Lambda execution role has minimal permissions (least privilege)
- API tokens stored in AWS Secrets Manager
- All changes logged to CloudTrail
- Approval workflows for sensitive roles
- Exclusion rules prevent over-remediation
- IMDSv2 enforced on EC2 instances

## Troubleshooting

### Lambda Function Fails

1. Check CloudWatch logs: `/aws/lambda/ProcessFindingsFunction`
2. Verify IAM permissions in `iam_stack.py`
3. Verify the configured Amazon Bedrock models are current and enabled in your Region. If the logs show an Amazon Bedrock error that a model is legacy, deprecated, or not available, the shipped default model IDs have likely been retired - update `BEDROCK_CODEGEN_MODEL` and `BEDROCK_EXPLANATION_MODEL` (see [Amazon Bedrock model selection](#amazon-bedrock-model-selection)) to current models you have enabled, then redeploy.
4. Check CI/CD API token in Secrets Manager

### No Findings Generated

1. Verify IAM Access Analyzer is enabled
2. Check that roles have CloudTrail activity
3. Verify that the analysis period is set correctly (default: 90 days)

### PR/Issue Creation Fails

1. Verify CI/CD API token is valid
2. Check repository permissions
3. Verify that the repository exists and is accessible
4. Review CI/CD integration logs

## Cost Estimation

- **AWS Lambda:** Minimal cost at daily execution
- **Amazon Bedrock:** Token-based pricing for input and output
- **AWS CloudTrail:** Included (if already enabled)
- **IAM Access Analyzer:** Unused Access Analyzer is charged per analyzer per month based on the number of IAM roles and users analyzed; External Access Analyzer is free. See [IAM Access Analyzer pricing](https://aws.amazon.com/iam/access-analyzer/pricing/) for current rates.
- See current pricing at [AWS pricing](https://aws.amazon.com/pricing/) and the [IAM Access Analyzer pricing page](https://aws.amazon.com/iam/access-analyzer/pricing/)

## Clean Up

To remove all resources created by this solution:

```bash
cd infrastructure
cdk destroy --all
```

WARNING: This permanently deletes the Lambda function, EventBridge rule, CloudWatch alarms, and IAM roles. This action cannot be undone.

Note: `cdk destroy` does NOT delete the Lambda-created CloudWatch Logs log group. To remove it and stop incurring log storage charges:

```bash
aws logs delete-log-group --log-group-name /aws/lambda/ProcessFindingsFunction
```

WARNING: This permanently deletes all execution logs.

If you created the IAM Access Analyzer specifically for this solution, delete it separately:

```bash
aws accessanalyzer delete-analyzer --analyzer-name unused-access-analyzer
```

WARNING: Deleting the analyzer permanently removes all findings, analysis history, and unused permission data. Export any findings you need to retain before deletion.

If you stored a CI/CD API token in Secrets Manager, delete it manually:

```bash
aws secretsmanager delete-secret \
  --secret-id iam-remediation/gitlab-token \
  --recovery-window-in-days 7
```

Resources continue to incur AWS charges until they are deleted.

## Contributing

1. Create a feature branch
2. Make changes and test
3. Submit a merge request
4. Verify that all tests pass

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review CloudWatch logs
3. Open an issue in the repository

## Related Resources

- [AWS IAM Access Analyzer Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Refine unused access using IAM Access Analyzer recommendations](https://aws.amazon.com/blogs/security/refine-unused-access-using-iam-access-analyzer-recommendations/)
- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)
- [Amazon Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)

## Conclusion

This solution provides an automated approach to maintaining least-privilege AWS Identity and Access Management (IAM) permissions using AWS IAM Access Analyzer, AWS CloudTrail, and Amazon Bedrock. By combining role attribution with AI-generated infrastructure code, teams can remediate unused permissions through the same code review and issue tracking workflows they already follow. The dual-path design (PRs for IaC roles, issues for manual roles) acknowledges that not every role starts in IaC, and gradually shifts your environment toward code-driven remediation over time.

Get started by following the Quick Start above. Once deployed, run in dry-run mode first to validate role classification and tune exclusions before generating real PRs and issues.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
