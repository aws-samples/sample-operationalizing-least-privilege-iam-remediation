#!/usr/bin/env python3
"""
IAM Permission Remediation Solution - CDK App

This CDK application deploys the infrastructure for automated IAM permission
remediation based on IAM Access Analyzer findings.

The solution:
1. Monitors IAM Access Analyzer for unused permission findings
2. Traces role origin via CloudTrail (IaC vs manual)
3. Creates PRs for IaC-managed roles or issues for manual roles
4. Integrates with CI/CD platforms (GitLab, GitHub, etc.)
"""

import aws_cdk as cdk
from stacks.remediation_stack import RemediationStack
from stacks.iam_stack import IAMStack

app = cdk.App()

# Stack 1: IAM roles and policies (no dependencies)
iam_stack = IAMStack(
    app,
    "IAMRemediationStack",
    description="IAM roles and policies for remediation solution"
)

# Stack 2: Main remediation infrastructure (depends on IAM stack)
remediation_stack = RemediationStack(
    app,
    "IAMRemediationInfrastructure",
    lambda_execution_role=iam_stack.lambda_execution_role,
    description="Lambda functions, EventBridge rules, and integrations"
)
remediation_stack.add_dependency(iam_stack)

app.synth()
