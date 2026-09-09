"""
GitLab Integration

Creates merge requests and issues in GitLab for remediation.
"""

import logging
import os
import json
import boto3
import requests
from typing import Dict, Any, List

logger = logging.getLogger()


class GitLabIntegration:
    """GitLab API integration for creating MRs and issues"""

    def __init__(self):
        # GitLab API endpoint. Defaults to the public GitLab.com service URL;
        # set GITLAB_BASE_URL to point at a self-managed GitLab instance. An
        # empty string is treated the same as unset.
        self.base_url = os.environ.get("GITLAB_BASE_URL") or "https://gitlab.com"
        self.token = self._get_api_token()
        self.iac_repository = os.environ.get("GITLAB_IAC_REPOSITORY", "")
        self.headers = {
            "PRIVATE-TOKEN": self.token,
            "Content-Type": "application/json"
        }

    def _get_api_token(self) -> str:
        """Get GitLab API token from Secrets Manager"""
        try:
            secret_name = os.environ.get("CI_CD_TOKEN_SECRET", "iam-remediation/gitlab-token")
            secrets_client = boto3.client("secretsmanager")
            response = secrets_client.get_secret_value(SecretId=secret_name)
            return response.get("SecretString", "")
        except Exception as e:
            logger.warning(f"Error retrieving GitLab token: {str(e)}")
            raise

    def create_remediation_pr(
        self,
        repository: str,
        role_arn: str,
        unused_permissions: List[str],
        remediation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a merge request for IaC-managed role remediation
        
        Args:
            repository: GitLab repository (org/repo)
            role_arn: ARN of the role
            unused_permissions: List of unused permissions
            remediation_data: Remediation data with code changes and diffs
            
        Returns:
            Result dictionary with success status and MR URL
        """
        try:
            logger.info(f"Creating GitLab MR for role: {role_arn}")
            
            role_name = role_arn.split("/")[-1]
            branch_name = f"remediation/iam-{role_name}-{self._get_timestamp()}"
            
            # Create branch
            self._create_branch(repository, branch_name)
            
            # Create commit with changes
            commit_message = f"Remediate unused permissions in {role_name}\n\n" \
                           f"Unused permissions: {', '.join(unused_permissions)}\n" \
                           f"Role ARN: {role_arn}"
            
            self._create_commit(
                repository,
                branch_name,
                commit_message,
                remediation_data
            )
            
            # Create merge request
            mr_data = {
                "title": f"Remediate unused permissions in {role_name}",
                "description": self._generate_mr_description(
                    role_arn,
                    unused_permissions,
                    remediation_data
                ),
                "source_branch": branch_name,
                "target_branch": "main",
                "labels": ["security", "iam-remediation"],
                "assignee_ids": self._get_assignee_ids()
            }
            
            mr_response = self._create_merge_request(repository, mr_data)
            
            if mr_response.get("success"):
                return {
                    "success": True,
                    "pr_url": mr_response.get("web_url"),
                    "mr_iid": mr_response.get("iid")
                }
            else:
                return {
                    "success": False,
                    "error": mr_response.get("error")
                }
            
        except Exception as e:
            logger.error(f"Error creating GitLab MR: {str(e)}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
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
        Create an issue for manual role remediation
        
        Args:
            role_arn: ARN of the role
            unused_permissions: List of unused permissions
            remediation_data: Remediation data with policy and guidance
            created_by: User who created the role
            created_at: When the role was created
            
        Returns:
            Result dictionary with success status and issue URL
        """
        try:
            logger.info(f"Creating GitLab issue for role: {role_arn}")
            
            role_name = role_arn.split("/")[-1]
            
            issue_data = {
                "title": f"Import manually-created role into IaC: {role_name}",
                "description": self._generate_issue_description(
                    role_arn,
                    unused_permissions,
                    remediation_data,
                    created_by,
                    created_at
                ),
                "labels": ["security", "iam-remediation", "manual-role"],
                "assignee_ids": self._get_assignee_ids()
            }
            
            issue_response = self._create_issue(self.iac_repository, issue_data)
            
            if issue_response.get("success"):
                return {
                    "success": True,
                    "issue_url": issue_response.get("web_url"),
                    "issue_iid": issue_response.get("iid")
                }
            else:
                return {
                    "success": False,
                    "error": issue_response.get("error")
                }
            
        except Exception as e:
            logger.error(f"Error creating GitLab issue: {str(e)}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def _create_branch(self, repository: str, branch_name: str) -> None:
        """Create a new branch in GitLab"""
        try:
            url = f"{self.base_url}/api/v4/projects/{self._encode_project_id(repository)}/repository/branches"
            data = {
                "branch": branch_name,
                "ref": "main"
            }
            response = requests.post(url, json=data, headers=self.headers, timeout=30)
            response.raise_for_status()
            logger.info(f"Created branch: {branch_name}")
        except Exception as e:
            logger.warning(f"Error creating branch: {str(e)}")
            raise

    def create_unused_role_issue(
        self,
        role_arn: str,
        remediation_data: Dict[str, Any],
        created_by: str = "Unknown",
        created_at: str = "Unknown"
    ) -> Dict[str, Any]:
        """
        Create a GitLab issue for a completely unused IAM role.

        Recommends soft-disable → monitor → delete workflow.
        """
        try:
            role_name = role_arn.split("/")[-1]
            logger.info(f"Creating GitLab issue for unused role: {role_name}")

            role_info = remediation_data.get("role_info", {})
            attached = remediation_data.get("attached_policies", [])
            inline = remediation_data.get("inline_policies", [])
            deny_policy = remediation_data.get("deny_all_policy", "")
            principals = role_info.get("trust_principals", [])
            tags = role_info.get("tags", {})

            tags_str = "\n".join(f"- `{k}`: `{v}`" for k, v in tags.items()) if tags else "- None"
            attached_str = "\n".join(f"- `{p}`" for p in attached) if attached else "- None"
            inline_str = "\n".join(f"- `{p}`" for p in inline) if inline else "- None"
            principals_str = ", ".join(f"`{p}`" for p in principals) if principals else "Unknown"

            description = f"""## ⚠️ Unused IAM Role Detected

**Role:** `{role_arn}`
**Created:** {role_info.get('create_date', created_at)}
**Created By:** {created_by}
**Finding Date:** {remediation_data.get('finding_created_at', 'Unknown')}
**Last Analyzed:** {remediation_data.get('analyzed_at', 'Unknown')}
**Trust Principals:** {principals_str}

### Why This Was Flagged

IAM Access Analyzer determined this role has **not been assumed** within the analysis period. Unused roles expand your attack surface unnecessarily.

### Role Details

**Attached Managed Policies:**
{attached_str}

**Inline Policies:**
{inline_str}

**Tags:**
{tags_str}

### Recommended Remediation (3-Phase)

#### Phase 1: Soft-Disable (Immediate)
Attach a deny-all inline policy. This prevents the role from doing anything if assumed, without deleting it. If something breaks, you can instantly revert by removing this policy.

```bash
aws iam put-role-policy \\
    --role-name {role_name} \\
    --policy-name DenyAll-SoftDisable \\
    --policy-document '{deny_policy}'
```

#### Phase 2: Monitor (7–14 days)
Watch for any errors or service disruptions. Check CloudTrail for any `AssumeRole` attempts:

```bash
aws cloudtrail lookup-events \\
    --lookup-attributes AttributeKey=ResourceName,AttributeValue={role_name} \\
    --start-time $(date -u -v-14d +%Y-%m-%dT%H:%M:%SZ) \\
    --region us-east-1
```

#### Phase 3: Delete (After monitoring period)
If no issues arise, remove the role:

```bash
# Remove inline policies
{self._generate_cleanup_commands(role_name, inline)}

# Detach managed policies
{self._generate_detach_commands(role_name, attached)}

# Delete the role
aws iam delete-role --role-name {role_name}
```

### CDK Equivalent (if importing to IaC for deletion tracking)
```python
# Add to your CDK stack to track the deletion in version control
# This creates a removal record — deploy to delete the role
from aws_cdk import RemovalPolicy
# Role '{role_name}' scheduled for deletion — see issue for context
```

---
*Generated by IAM Permission Remediation Solution*
*Finding type: UnusedIAMRole*
"""

            issue_data = {
                "title": f"🗑️ Unused IAM Role: {role_name}",
                "description": description,
                "labels": ["security", "iam-remediation", "unused-role"],
                "assignee_ids": self._get_assignee_ids()
            }

            issue_response = self._create_issue(self.iac_repository, issue_data)

            if issue_response.get("success"):
                return {
                    "success": True,
                    "issue_url": issue_response.get("web_url"),
                    "issue_iid": issue_response.get("iid")
                }
            else:
                return {
                    "success": False,
                    "error": issue_response.get("error")
                }

        except Exception as e:
            logger.error(f"Error creating unused role issue: {str(e)}", exc_info=True)
            return {"success": False, "error": str(e)}

    def _generate_cleanup_commands(self, role_name: str, inline_policies: List[str]) -> str:
        """Generate CLI commands to remove inline policies"""
        if not inline_policies:
            return "# No inline policies to remove"
        return "\n".join(
            f"aws iam delete-role-policy --role-name {role_name} --policy-name {p}"
            for p in inline_policies
        )

    def _generate_detach_commands(self, role_name: str, attached_policies: List[str]) -> str:
        """Generate CLI commands to detach managed policies"""
        if not attached_policies:
            return "# No managed policies to detach"
        return "\n".join(
            f"aws iam detach-role-policy --role-name {role_name} --policy-arn $(aws iam list-attached-role-policies --role-name {role_name} --query \"AttachedPolicies[?PolicyName=='{p}'].PolicyArn\" --output text)"
            for p in attached_policies
        )


    def _create_commit(
        self,
        repository: str,
        branch_name: str,
        message: str,
        remediation_data: Dict[str, Any]
    ) -> None:
        """Create a commit with remediation changes"""
        try:
            url = f"{self.base_url}/api/v4/projects/{self._encode_project_id(repository)}/repository/commits"
            
            # Prepare file changes - include CDK code, policy diff, and explanation
            role_name = remediation_data.get("role_name", "unknown")
            
            # Build remediation content for the commit
            remediation_content = f"""# IAM Permission Remediation: {role_name}

## Explanation
{remediation_data.get('explanation', 'Removing unused permissions')}

## Policy Diff
```diff
{remediation_data.get('policy_diff', '')}
```

## Recommended Policy (from IAM Access Analyzer)
```json
{json.dumps(remediation_data.get('recommended_policy', {}), indent=2)}
```

## CDK Code
```python
{remediation_data.get('cdk_code', '')}
```
"""
            
            actions = [
                {
                    "action": "create",
                    "file_path": f"roles/{role_name}_remediation.md",
                    "content": remediation_content
                }
            ]
            
            data = {
                "branch": branch_name,
                "commit_message": message,
                "actions": actions
            }
            
            response = requests.post(url, json=data, headers=self.headers, timeout=30)
            response.raise_for_status()
            logger.info(f"Created commit in branch: {branch_name}")
        except Exception as e:
            logger.warning(f"Error creating commit: {str(e)}")
            raise

    def _create_merge_request(
        self,
        repository: str,
        mr_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a merge request"""
        try:
            url = f"{self.base_url}/api/v4/projects/{self._encode_project_id(repository)}/merge_requests"
            response = requests.post(url, json=mr_data, headers=self.headers, timeout=30)
            response.raise_for_status()
            result = response.json()
            return {
                "success": True,
                "web_url": result.get("web_url"),
                "iid": result.get("iid")
            }
        except Exception as e:
            logger.warning(f"Error creating merge request: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def _create_issue(
        self,
        repository: str,
        issue_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create an issue"""
        try:
            url = f"{self.base_url}/api/v4/projects/{self._encode_project_id(repository)}/issues"
            response = requests.post(url, json=issue_data, headers=self.headers, timeout=30)
            response.raise_for_status()
            result = response.json()
            return {
                "success": True,
                "web_url": result.get("web_url"),
                "iid": result.get("iid")
            }
        except Exception as e:
            logger.warning(f"Error creating issue: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def _generate_mr_description(
        self,
        role_arn: str,
        unused_permissions: List[str],
        remediation_data: Dict[str, Any]
    ) -> str:
        """Generate merge request description"""
        return f"""
## IAM Permission Remediation

**Role:** {role_arn}

**Summary:**
{remediation_data.get('explanation', 'Removing unused permissions')}

**Unused Permissions:**
{chr(10).join(f"- {perm}" for perm in unused_permissions)}

**Policy Diff:**
```diff
{remediation_data.get('policy_diff', '')}
```

**CDK Code Changes:**
```python
{remediation_data.get('cdk_code', '')}
```

**Code Generation Notes:**
- CDK code generated by Amazon Bedrock (Claude)
- Validation: {'✅ Passed' if remediation_data.get('cdk_validation_passed') else '⚠️ Review Required'}

**Context:**
- Permissions have not been used in the last 90 days
- This change removes unused permissions to improve security posture
- Please review the policy diff and generated code to ensure no critical functionality is affected

**Next Steps:**
1. Review the changes and generated CDK code
2. Test in a non-production environment
3. Merge to deploy
"""

    def _generate_issue_description(
        self,
        role_arn: str,
        unused_permissions: List[str],
        remediation_data: Dict[str, Any],
        created_by: str,
        created_at: str
    ) -> str:
        """Generate issue description"""
        return f"""
## Import Manually-Created Role into IaC

**Role:** {role_arn}
**Created By:** {created_by}
**Created At:** {created_at}

**Unused Permissions:**
{chr(10).join(f"- {perm}" for perm in unused_permissions)}

**Recommended Policy (from IAM Access Analyzer):**
```json
{json.dumps(remediation_data.get('recommended_policy', {}), indent=2)}
```

**Explanation:**
{remediation_data.get('explanation', '')}

**Import Guidance:**
{remediation_data.get('import_guidance', '')}

**Why This Matters:**
- Manually-created roles lack version control and code review
- Importing into IaC enables automated remediation for future findings
- Ensures consistent configuration across environments
"""

    def _get_assignee_ids(self) -> List[int]:
        """Get assignee IDs from configuration"""
        # In production, this would read from configuration
        return []

    def _encode_project_id(self, repository: str) -> str:
        """Encode project ID for GitLab API"""
        return repository.replace("/", "%2F")

    def _get_timestamp(self) -> str:
        """Get current timestamp for branch naming"""
        from datetime import datetime
        return datetime.utcnow().strftime("%Y%m%d%H%M%S")
