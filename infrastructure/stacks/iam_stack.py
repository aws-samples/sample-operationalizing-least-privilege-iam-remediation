"""
IAM Stack - Roles and Policies for Remediation Solution

This stack creates the IAM execution role for Lambda functions with
least-privilege permissions required for the remediation workflow.
It also creates the IAM Access Analyzer for detecting unused permissions.
"""

import aws_cdk as cdk
from aws_cdk import (
    aws_iam as iam,
    aws_accessanalyzer as analyzer,
)
from constructs import Construct


class IAMStack(cdk.Stack):
    """
    Creates IAM roles, policies, and Access Analyzer for the remediation solution.

    AWS Identity and Access Management Access Analyzer Types:
    - ACCOUNT: Analyzes external access (who outside can access your resources)
    - ACCOUNT_UNUSED_ACCESS: Analyzes unused permissions (what permissions aren't being used)

    We use ACCOUNT_UNUSED_ACCESS because we want to identify and remediate
    permissions that roles have but aren't using.
    
    Permissions granted:
    - Read IAM Access Analyzer findings and generate recommendations
    - Query CloudTrail for role attribution
    - Read IAM role policies
    - Secrets Manager access for CI/CD tokens
    - CloudWatch Logs for function logging
    - Amazon Bedrock for CDK code generation
    
    Permissions NOT granted (least privilege):
    - IAM role modification
    - IAM policy modification
    - Secrets Manager write access
    - Lambda function modification
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # IAM Access Analyzer for detecting UNUSED PERMISSIONS
        # Note: Only one ACCOUNT_UNUSED_ACCESS analyzer is allowed per account.
        # We reference the existing analyzer instead of creating a new one.
        # If no analyzer exists, create one manually:
        #   aws accessanalyzer create-analyzer --analyzer-name unused-access-analyzer \
        #     --type ACCOUNT_UNUSED_ACCESS \
        #     --configuration '{"unusedAccess": {"unusedAccessAge": 1}}'
        
        # Store the existing analyzer ARN for reference
        self.access_analyzer_arn = f"arn:aws:access-analyzer:{self.region}:{self.account}:analyzer/unused-access-analyzer"

        # Lambda execution role
        self.lambda_execution_role = iam.Role(
            self,
            "RemediationLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Execution role for IAM remediation Lambda functions"
        )

        # CloudWatch Logs permissions (required for Lambda logging)
        self.lambda_execution_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            )
        )

        # IAM Access Analyzer permissions (including V2 APIs and recommendations)
        # Note: Access Analyzer service-level actions (ListAnalyzers, GetFinding, etc.)
        # do not support resource-level permissions per AWS API design.
        # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamaccessanalyzer.html
        self.lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "access-analyzer:ListAnalyzers",
                    "access-analyzer:ListFindings",
                    "access-analyzer:ListFindingsV2",
                    "access-analyzer:GetFinding",
                    "access-analyzer:GetFindingV2",
                    "access-analyzer:GetFindingRecommendation",
                    "access-analyzer:GenerateFindingRecommendation",
                    "access-analyzer:CheckNoNewAccess",
                ],
                resources=["*"]  # REQUIRED by AWS API design - Access Analyzer service-level actions (ListAnalyzers, GetFinding, etc.) do not support resource-level permissions per AWS documentation: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamaccessanalyzer.html
            )
        )

        # CloudTrail read-only permissions for role attribution
        # Note: cloudtrail:LookupEvents does not support resource-level permissions
        # per AWS API design.
        # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awscloudtrail.html
        self.lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "cloudtrail:LookupEvents"
                ],
                resources=["*"]  # REQUIRED by AWS API design - cloudtrail:LookupEvents does not support resource-level permissions per AWS documentation: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awscloudtrail.html
            )
        )

        # IAM read-only permissions
        # Note: Lambda needs to read metadata for any role in the account to determine origin.
        # Scoping to specific role ARNs is not feasible because the solution discovers roles
        # dynamically via Access Analyzer findings. All actions below are read-only (Get*, List*).
        self.lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "iam:GetRole",
                    "iam:GetRolePolicy",
                    "iam:ListRolePolicies",
                    "iam:ListAttachedRolePolicies",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:ListRoleTags"
                ],
                resources=["*"]  # REQUIRED for dynamic role discovery - Lambda needs to read metadata for any role in the account to determine origin. Scoping to specific role ARNs is not feasible because the solution discovers roles dynamically via Access Analyzer findings. All actions are read-only (Get*, List*).
            )
        )

        # Organizations read-only (for org-level analyzer support)
        # Note: Organizations actions (ListAccounts, DescribeOrganization) do not support
        # resource-level permissions per AWS API design.
        # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html
        self.lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "organizations:ListAccounts",
                    "organizations:DescribeOrganization"
                ],
                resources=["*"]  # REQUIRED by AWS API design - Organizations actions (ListAccounts, DescribeOrganization) do not support resource-level permissions per AWS documentation: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html
            )
        )

        # STS AssumeRole for cross-account CloudTrail/IAM queries
        self.lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "sts:AssumeRole"
                ],
                resources=["arn:aws:iam::*:role/OrganizationAccountAccessRole"]
            )
        )

        # Secrets Manager read-only permissions for CI/CD tokens
        self.lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:GetSecretValue"
                ],
                resources=[
                    f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:iam-remediation/*"
                ]
            )
        )

        # CloudWatch metrics permissions
        # Note: cloudwatch:PutMetricData does not support resource-level permissions
        # per AWS API design. Namespace condition restricts publishing to our metric namespace only.
        # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatch.html
        self.lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "cloudwatch:PutMetricData"
                ],
                resources=["*"],  # REQUIRED by AWS API design - cloudwatch:PutMetricData does not support resource-level permissions per AWS documentation: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatch.html
                conditions={
                    "StringEquals": {
                        "cloudwatch:namespace": "IAMRemediation"
                    }
                }
            )
        )

        # Amazon Bedrock permissions for CDK code generation and explanations.
        # Scoped to Anthropic models on Bedrock (inference profiles in this account +
        # the foundation models they route to across regions). Using a model-family
        # wildcard rather than specific model IDs so the configured model can be changed
        # via the BEDROCK_*_MODEL env vars without requiring an IAM policy update.
        self.lambda_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "bedrock:InvokeModel"
                ],
                resources=[
                    # Cross-region inference profiles for Anthropic models in this account
                    f"arn:aws:bedrock:*:{self.account}:inference-profile/*anthropic*",
                    # Foundation models the inference profiles route to (multi-region, account-less ARNs)
                    "arn:aws:bedrock:*::foundation-model/anthropic.*"
                ]
            )
        )

        # Output the role ARN for use in other stacks
        cdk.CfnOutput(
            self,
            "LambdaExecutionRoleArn",
            value=self.lambda_execution_role.role_arn,
            description="ARN of Lambda execution role"
        )

        # Output the analyzer ARN
        cdk.CfnOutput(
            self,
            "AccessAnalyzerArn",
            value=self.access_analyzer_arn,
            description="ARN of IAM Access Analyzer (Unused Access type)"
        )
