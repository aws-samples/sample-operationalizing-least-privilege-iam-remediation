"""
Main AWS Lambda Handler - Process AWS Identity and Access Management (IAM) Access Analyzer Findings

This function:
1. Queries AWS Identity and Access Management Access Analyzer for unused permission findings
2. Filters findings against exclusion rules
3. For each finding, determines role origin via AWS CloudTrail
4. Routes to appropriate remediation path (IaC or manual)
5. Creates PRs or issues in CI/CD system
6. Publishes metrics to Amazon CloudWatch
"""

import json
import logging
import os
import fnmatch
import boto3
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from analyzer import AccessAnalyzerClient
from cloudtrail import CloudTrailClient
from remediation import RemediationGenerator
from ci_cd_integrations.gitlab import GitLabIntegration
from ci_cd_integrations.github import GitHubIntegration
from ci_cd_integrations.dryrun import DryRunIntegration

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class ExclusionFilter:
    """Loads and evaluates exclusion rules against findings."""

    def __init__(self):
        self.config = self._load_config()
        self.iam_client = boto3.client("iam")

    def _load_config(self) -> Dict[str, Any]:
        """Load exclusion config from AWS Secrets Manager or return empty defaults."""
        secret_name = os.environ.get("EXCLUSIONS_CONFIG")
        if not secret_name:
            logger.info("No EXCLUSIONS_CONFIG env var set, skipping exclusions")
            return {}
        try:
            sm = boto3.client("secretsmanager")
            response = sm.get_secret_value(SecretId=secret_name)
            config = json.loads(response["SecretString"])
            logger.info(f"Loaded exclusion config from {secret_name}")
            return config
        except Exception as e:
            logger.warning(f"Failed to load exclusion config from {secret_name}: {e}")
            return {}

    def should_exclude(self, finding: Dict[str, Any]) -> bool:
        """Check whether a finding should be skipped based on exclusion rules.

        Checks in order:
        1. Role ARN against excluded_roles (supports * wildcards)
        2. Role tags against excluded_by_tag
        3. min_unused_days threshold
        """
        if not self.config:
            return False

        finding_details = finding.get("details", {})
        role_arn = finding_details.get("resource", "")
        role_name = role_arn.split("/")[-1] if role_arn else ""

        # 1. Check excluded role ARNs
        for pattern in self.config.get("excluded_roles", []):
            if fnmatch.fnmatch(role_arn, pattern):
                logger.info(f"Excluding {role_name}: matches excluded_roles pattern '{pattern}'")
                return True

        # 2. Check excluded tags
        excluded_tags = self.config.get("excluded_by_tag", {})
        if excluded_tags and role_name:
            try:
                role_tags = self.iam_client.list_role_tags(RoleName=role_name).get("Tags", [])
                tag_map = {t["Key"]: t["Value"] for t in role_tags}
                for tag_key, tag_values in excluded_tags.items():
                    if tag_map.get(tag_key) in tag_values:
                        logger.info(f"Excluding {role_name}: tag {tag_key}={tag_map[tag_key]}")
                        return True
            except Exception as e:
                logger.warning(f"Could not check tags for {role_name}: {e}")

        # 3. Check min_unused_days
        min_days = self.config.get("min_unused_days", 0)
        if min_days > 0:
            analyzed_at = finding_details.get("analyzedAt")
            updated_at = finding_details.get("updatedAt")
            created_at = finding_details.get("createdAt")
            # Use the finding creation date as a proxy for when the permission
            # was first detected as unused
            ref_date = created_at or updated_at or analyzed_at
            if ref_date:
                try:
                    if isinstance(ref_date, str):
                        ref_dt = datetime.fromisoformat(ref_date.replace("Z", "+00:00"))
                    else:
                        ref_dt = ref_date
                    days_unused = (datetime.now(timezone.utc) - ref_dt).days
                    if days_unused < min_days:
                        logger.info(
                            f"Excluding {role_name}: only {days_unused} days unused "
                            f"(min: {min_days})"
                        )
                        return True
                except Exception as e:
                    logger.warning(f"Could not parse date for min_unused_days check: {e}")

        return False


class RemediationOrchestrator:
    """Orchestrates the remediation workflow"""

    def __init__(self):
        self.analyzer = AccessAnalyzerClient()
        self.cloudtrail = CloudTrailClient()
        self.remediation = RemediationGenerator()
        self.ci_cd_platform = os.environ.get("CI_CD_PLATFORM", "gitlab")
        self.ci_cd_client = self._get_ci_cd_client()
        self.exclusion_filter = ExclusionFilter()
        self.cloudwatch = boto3.client("cloudwatch")
        self.metrics = {
            "findings_processed": 0,
            "iac_roles_found": 0,
            "manual_roles_found": 0,
            "unused_roles_found": 0,
            "prs_created": 0,
            "issues_created": 0,
            "errors": 0
        }

    def _get_ci_cd_client(self):
        """Get CI/CD integration client based on platform"""
        if self.ci_cd_platform == "gitlab":
            return GitLabIntegration()
        elif self.ci_cd_platform == "github":
            return GitHubIntegration()
        elif self.ci_cd_platform == "dryrun":
            return DryRunIntegration()
        else:
            raise ValueError(f"Unsupported CI/CD platform: {self.ci_cd_platform}")

    def process_findings(self) -> Dict[str, Any]:
        """
        Main workflow: process all findings and create remediation items
        
        Returns:
            Dictionary with processing results and metrics
        """
        try:
            logger.info("Starting remediation workflow")
            
            # Process UnusedPermission findings (roles with excess permissions)
            findings = self.analyzer.get_findings()
            logger.info(f"Found {len(findings)} unused permission findings")
            
            max_findings = int(os.environ.get("MAX_FINDINGS_PER_RUN", "50"))
            processed = 0
            
            for finding in findings:
                if processed >= max_findings:
                    logger.info(
                        f"Reached max_findings_per_run limit ({max_findings}), "
                        f"remaining findings will be processed on next run"
                    )
                    break
                
                if self.exclusion_filter.should_exclude(finding):
                    continue
                
                self._process_finding(finding)
                processed += 1
            
            # Process UnusedIAMRole findings (roles never assumed)
            max_unused_role_issues = int(os.environ.get("MAX_UNUSED_ROLE_ISSUES", "10"))
            unused_role_findings = self.analyzer.get_unused_role_findings(max_results=max_unused_role_issues)
            logger.info(f"Found {len(unused_role_findings)} unused IAM role findings (limit: {max_unused_role_issues})")
            
            for finding in unused_role_findings:
                if self.exclusion_filter.should_exclude(finding):
                    continue
                self._handle_unused_role(finding)
            
            # Publish metrics to CloudWatch
            self._publish_metrics()
            
            logger.info(f"Remediation workflow complete. Metrics: {self.metrics}")
            return {
                "statusCode": 200,
                "message": "Remediation workflow completed",
                "metrics": self.metrics
            }
            
        except Exception as e:
            logger.error(f"Error in remediation workflow: {str(e)}", exc_info=True)
            self.metrics["errors"] += 1
            self._publish_metrics()
            return {
                "statusCode": 500,
                "message": f"Error in remediation workflow: {str(e)}",
                "metrics": self.metrics
            }

    def _publish_metrics(self) -> None:
        """Publish processing metrics to CloudWatch."""
        try:
            timestamp = datetime.now(timezone.utc)
            metric_data = [
                {
                    "MetricName": name,
                    "Value": value,
                    "Timestamp": timestamp,
                    "Unit": "Count",
                }
                for name, value in self.metrics.items()
            ]
            self.cloudwatch.put_metric_data(
                Namespace="IAMRemediation",
                MetricData=metric_data,
            )
            logger.info("Published metrics to CloudWatch namespace IAMRemediation")
        except Exception as e:
            logger.warning(f"Failed to publish CloudWatch metrics: {e}")

    def _process_finding(self, finding: Dict[str, Any]) -> None:
        """
        Process a single finding:
        1. Determine role origin
        2. Generate remediation using Access Analyzer recommendation
        3. Create PR or issue
        
        Note: Finding now includes 'details' and 'recommendation' from analyzer.py
        The recommendation contains the Access Analyzer recommended policy.
        """
        try:
            self.metrics["findings_processed"] += 1
            
            # Get role ARN from finding details
            finding_details = finding.get("details", {})
            role_arn = finding_details.get("resource")
            if not role_arn:
                logger.warning("Finding missing resource ARN, skipping")
                return
            
            # Get account ID (from org-level findings or default to local account)
            account_id = finding.get("account_id", self.analyzer.account_id)
            
            # Check if we have a valid recommendation
            recommendation = finding.get("recommendation", {})
            if recommendation.get("status") != "SUCCEEDED":
                logger.warning(f"No valid recommendation for finding {finding.get('id')}, skipping")
                return
            
            logger.info(f"Processing finding for role: {role_arn} (account: {account_id})")
            logger.info(f"Recommendation status: {recommendation.get('status')}")
            
            # Determine role origin
            role_origin = self.cloudtrail.get_role_origin(role_arn, account_id=account_id)
            logger.info(f"Role origin: {role_origin}")
            
            if role_origin["type"] == "iac":
                self._handle_iac_role(role_arn, finding, role_origin)
            else:
                self._handle_manual_role(role_arn, finding, role_origin)
                
        except Exception as e:
            logger.error(f"Error processing finding: {str(e)}", exc_info=True)
            self.metrics["errors"] += 1

    def _handle_iac_role(
        self,
        role_arn: str,
        finding: Dict[str, Any],
        role_origin: Dict[str, Any]
    ) -> None:
        """Handle remediation for IaC-managed roles"""
        try:
            logger.info(f"Handling IaC-managed role: {role_arn}")
            self.metrics["iac_roles_found"] += 1
            
            # Generate remediation using Access Analyzer recommendation
            remediation_data = self.remediation.generate_iac_remediation(
                role_arn,
                finding,
                role_origin
            )
            
            if not remediation_data:
                logger.warning(f"No remediation data generated for {role_arn}, skipping PR creation")
                return
            
            # Create PR in repository
            pr_result = self.ci_cd_client.create_remediation_pr(
                repository=role_origin.get("repository"),
                role_arn=role_arn,
                unused_permissions=remediation_data.get("unused_permissions", []),
                remediation_data=remediation_data
            )
            
            if pr_result.get("success"):
                self.metrics["prs_created"] += 1
                logger.info(f"Created PR: {pr_result.get('pr_url')}")
            else:
                logger.error(f"Failed to create PR: {pr_result.get('error')}")
                self.metrics["errors"] += 1
                
        except Exception as e:
            logger.error(f"Error handling IaC role: {str(e)}", exc_info=True)
            self.metrics["errors"] += 1

    def _handle_manual_role(
        self,
        role_arn: str,
        finding: Dict[str, Any],
        role_origin: Dict[str, Any]
    ) -> None:
        """Handle remediation for manually-created roles"""
        try:
            logger.info(f"Handling manually-created role: {role_arn}")
            self.metrics["manual_roles_found"] += 1
            
            # Generate remediation using Access Analyzer recommendation
            remediation_data = self.remediation.generate_manual_remediation(
                role_arn,
                finding
            )
            
            if not remediation_data:
                logger.warning(f"No remediation data generated for {role_arn}, skipping issue creation")
                return
            
            # Create issue in tracking system
            issue_result = self.ci_cd_client.create_remediation_issue(
                role_arn=role_arn,
                unused_permissions=remediation_data.get("unused_permissions", []),
                remediation_data=remediation_data,
                created_by=role_origin.get("created_by"),
                created_at=role_origin.get("created_at")
            )
            
            if issue_result.get("success"):
                self.metrics["issues_created"] += 1
                logger.info(f"Created issue: {issue_result.get('issue_url')}")
            else:
                logger.error(f"Failed to create issue: {issue_result.get('error')}")
                self.metrics["errors"] += 1
                
        except Exception as e:
            logger.error(f"Error handling manual role: {str(e)}", exc_info=True)
            self.metrics["errors"] += 1

    def _handle_unused_role(self, finding: Dict[str, Any]) -> None:
        """Handle remediation for completely unused IAM roles"""
        try:
            finding_details = finding.get("details", {})
            role_arn = finding_details.get("resource")
            if not role_arn:
                logger.warning("Unused role finding missing resource ARN, skipping")
                return

            role_name = role_arn.split("/")[-1]
            account_id = finding.get("account_id", self.analyzer.account_id)
            logger.info(f"Handling unused IAM role: {role_name} (account: {account_id})")
            self.metrics["unused_roles_found"] += 1

            # Determine origin for context (best-effort)
            role_origin = self.cloudtrail.get_role_origin(role_arn, account_id=account_id)

            # Generate remediation data (soft-disable workflow)
            remediation_data = self.remediation.generate_unused_role_remediation(
                role_arn, finding
            )

            if not remediation_data:
                logger.warning(f"No remediation data for unused role {role_name}, skipping")
                return

            # Create GitLab issue with soft-disable → monitor → delete guidance
            issue_result = self.ci_cd_client.create_unused_role_issue(
                role_arn=role_arn,
                remediation_data=remediation_data,
                created_by=role_origin.get("created_by", "Unknown"),
                created_at=role_origin.get("created_at", "Unknown")
            )

            if issue_result.get("success"):
                self.metrics["issues_created"] += 1
                logger.info(f"Created unused role issue: {issue_result.get('issue_url')}")
            else:
                logger.error(f"Failed to create unused role issue: {issue_result.get('error')}")
                self.metrics["errors"] += 1

        except Exception as e:
            logger.error(f"Error handling unused role: {str(e)}", exc_info=True)
            self.metrics["errors"] += 1


def handler(event, context):
    """
    Lambda handler function
    
    Args:
        event: EventBridge event (contains trigger information)
        context: Lambda context
        
    Returns:
        Dictionary with status and results
    """
    logger.info(f"Remediation Lambda triggered at {datetime.now(timezone.utc).isoformat()}")
    logger.info(f"Event: {json.dumps(event)}")
    
    orchestrator = RemediationOrchestrator()
    result = orchestrator.process_findings()
    
    return result
