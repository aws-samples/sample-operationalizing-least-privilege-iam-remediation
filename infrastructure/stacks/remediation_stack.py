"""
Remediation Stack - AWS Lambda Functions and Amazon EventBridge Integration

This stack creates the AWS Lambda function that processes AWS Identity and Access
Management (IAM) Access Analyzer findings and creates PRs/issues in your CI/CD system.
"""

import aws_cdk as cdk
from aws_cdk import (
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    Duration,
)
from constructs import Construct
import os


class RemediationStack(cdk.Stack):
    """
    Creates AWS Lambda functions and Amazon EventBridge rules for the remediation workflow.

    Workflow:
    1. Amazon EventBridge triggers daily at configured time
    2. AWS Lambda function processes IAM Access Analyzer findings
    3. For each finding:
       - Query AWS CloudTrail to determine role origin
       - If IaC-managed: Create PR with code changes and policy diff
       - If manual: Create issue with policy and import guidance
    4. Publish metrics to Amazon CloudWatch
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        lambda_execution_role: iam.Role,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Lambda function for processing findings
        # Dependencies are pre-installed in the package/ subdirectory.
        # To refresh: pip install -r requirements.txt -t package/ --upgrade
        lambda_path = os.path.join(os.path.dirname(__file__), "../../lambda/process_findings")
        self.process_findings_lambda = lambda_.Function(
            self,
            "ProcessFindingsFunction",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_asset(lambda_path),
            role=lambda_execution_role,
            timeout=Duration.minutes(5),
            memory_size=512,
            description="Process IAM Access Analyzer findings and create remediation PRs/issues",
            environment={
                "CI_CD_PLATFORM": "dryrun",  # gitlab, github, or dryrun
                "CI_CD_TOKEN_SECRET": "iam-remediation/gitlab-token",
                # Per-deployment config knob. Empty default; gitlab.py falls back
                # to the public GitLab.com endpoint when this is unset. Override
                # this value to point at a self-managed GitLab instance.
                "GITLAB_BASE_URL": "",
                "GITLAB_IAC_REPOSITORY": "your-org/iac-repo",
                "EXCLUSIONS_CONFIG": "iam-remediation/exclusions",
                "APPROVAL_WORKFLOWS_CONFIG": "iam-remediation/approval-workflows",
                "ANALYZER_SCOPE": "organization",  # account or organization
                "CROSS_ACCOUNT_ROLE_NAME": "OrganizationAccountAccessRole",
                "MAX_FINDINGS_PER_RUN": "50",
                "MAX_UNUSED_ROLE_ISSUES": "10",
                # Amazon Bedrock model IDs (cross-region inference profiles). Override these
                # to switch models without code changes; update if a model is deprecated.
                "BEDROCK_CODEGEN_MODEL": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
                "BEDROCK_EXPLANATION_MODEL": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
            }
        )

        # EventBridge rule to trigger daily
        remediation_rule = events.Rule(
            self,
            "RemediationScheduleRule",
            schedule=events.Schedule.cron(
                hour="2",  # 2 AM UTC
                minute="0"
            ),
            description="Daily trigger for IAM permission remediation"
        )

        # Add Lambda as target
        remediation_rule.add_target(
            targets.LambdaFunction(self.process_findings_lambda)
        )

        # CloudWatch Log Group for Lambda
        log_group = cdk.aws_logs.LogGroup(
            self,
            "RemediationLogGroup",
            log_group_name=f"/aws/lambda/{self.process_findings_lambda.function_name}",
            retention=cdk.aws_logs.RetentionDays.TWO_WEEKS,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )

        # CloudWatch Alarms
        error_alarm = cdk.aws_cloudwatch.Alarm(
            self,
            "RemediationErrorAlarm",
            metric=self.process_findings_lambda.metric_errors(),
            threshold=1,
            evaluation_periods=1,
            alarm_description="Alert when remediation Lambda has errors"
        )

        # Outputs
        cdk.CfnOutput(
            self,
            "LambdaFunctionName",
            value=self.process_findings_lambda.function_name,
            description="Name of the remediation Lambda function"
        )

        cdk.CfnOutput(
            self,
            "LambdaFunctionArn",
            value=self.process_findings_lambda.function_arn,
            description="ARN of the remediation Lambda function"
        )

        cdk.CfnOutput(
            self,
            "EventBridgeRuleArn",
            value=remediation_rule.rule_arn,
            description="ARN of the EventBridge rule"
        )
