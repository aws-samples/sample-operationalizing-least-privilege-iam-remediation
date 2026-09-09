"""
Dry Run Integration

Logs remediation actions without actually creating PRs/issues.
Useful for testing and environments without CI/CD integration.
"""

import logging
import json
from typing import Dict, Any, List

logger = logging.getLogger()


class DryRunIntegration:
    """Dry run integration that logs what would be created"""

    def __init__(self):
        logger.info("DryRunIntegration initialized - no actual PRs/issues will be created")

    def create_remediation_pr(
        self,
        repository: str,
        role_arn: str,
        unused_permissions: List[str],
        remediation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Log what PR would be created for IaC-managed role remediation
        """
        role_name = role_arn.split("/")[-1]
        
        pr_info = {
            "type": "merge_request",
            "repository": repository,
            "role_arn": role_arn,
            "role_name": role_name,
            "unused_permissions_count": len(unused_permissions),
            "unused_permissions_sample": unused_permissions[:10],  # First 10
            "title": f"Remediate unused permissions in {role_name}",
            "labels": ["security", "iam-remediation"],
            "remediation_summary": remediation_data.get("policy_summary", ""),
        }
        
        logger.info(f"[DRY RUN] Would create PR: {json.dumps(pr_info, indent=2)}")
        
        return {
            "success": True,
            "pr_url": f"[DRY RUN] PR for {role_name}",
            "dry_run": True,
            "details": pr_info
        }

    def create_remediation_issue(
        self,
        role_arn: str,
        unused_permissions: List[str],
        remediation_data: Dict[str, Any],
        created_by: str,
        created_at: str
    ) -> Dict[str, Any]:
        """
        Log what issue would be created for manual role remediation
        """
        role_name = role_arn.split("/")[-1]
        
        issue_info = {
            "type": "issue",
            "role_arn": role_arn,
            "role_name": role_name,
            "created_by": created_by,
            "created_at": created_at,
            "unused_permissions_count": len(unused_permissions),
            "unused_permissions_sample": unused_permissions[:10],  # First 10
            "title": f"Import manually-created role into IaC: {role_name}",
            "labels": ["security", "iam-remediation", "manual-role"],
        }
        
        logger.info(f"[DRY RUN] Would create issue: {json.dumps(issue_info, indent=2)}")
        
        return {
            "success": True,
            "issue_url": f"[DRY RUN] Issue for {role_name}",
            "dry_run": True,
            "details": issue_info
        }

    def create_unused_role_issue(
        self,
        role_arn: str,
        remediation_data: Dict[str, Any],
        created_by: str = "Unknown",
        created_at: str = "Unknown"
    ) -> Dict[str, Any]:
        """
        Log what issue would be created for an unused IAM role
        """
        role_name = role_arn.split("/")[-1]

        issue_info = {
            "type": "unused_role_issue",
            "role_arn": role_arn,
            "role_name": role_name,
            "created_by": created_by,
            "created_at": created_at,
            "attached_policies": remediation_data.get("attached_policies", []),
            "inline_policies": remediation_data.get("inline_policies", []),
            "title": f"🗑️ Unused IAM Role: {role_name}",
            "labels": ["security", "iam-remediation", "unused-role"],
        }

        logger.info(f"[DRY RUN] Would create unused role issue: {json.dumps(issue_info, indent=2)}")

        return {
            "success": True,
            "issue_url": f"[DRY RUN] Unused role issue for {role_name}",
            "dry_run": True,
            "details": issue_info
        }

