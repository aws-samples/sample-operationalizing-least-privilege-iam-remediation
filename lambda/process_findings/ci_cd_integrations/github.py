"""
GitHub Integration

Creates pull requests and issues in GitHub for remediation.
"""

import logging
import os
import base64
import boto3
import requests
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger()


class GitHubIntegration:
    """GitHub API integration for creating PRs and issues"""

    def __init__(self):
        # GitHub REST API base URL. This is the production GitHub API endpoint,
        # not a placeholder. For GitHub Enterprise Server, change to
        # https://<your-enterprise-host>/api/v3.
        self.base_url = "https://api.github.com"
        self.token = self._get_api_token()
        self.iac_repository = os.environ.get("GITHUB_IAC_REPOSITORY", "")
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    def _get_api_token(self) -> str:
        """Get GitHub API token from Secrets Manager"""
        try:
            secret_name = os.environ.get("CI_CD_TOKEN_SECRET", "iam-remediation/github-token")
            secrets_client = boto3.client("secretsmanager")
            response = secrets_client.get_secret_value(SecretId=secret_name)
            return response.get("SecretString", "")
        except Exception as e:
            logger.warning(f"Error retrieving GitHub token: {str(e)}")
            raise

    def create_remediation_pr(
        self,
        repository: str,
        role_arn: str,
        unused_permissions: List[str],
        remediation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a pull request for IaC-managed role remediation
        """
        try:
            # Use configured repository if none specified
            repo = repository or self.iac_repository
            if not repo:
                return {"success": False, "error": "No repository configured"}
            
            logger.info(f"Creating GitHub PR for role: {role_arn} in repo: {repo}")
            
            role_name = role_arn.split("/")[-1]
            branch_name = f"remediation/iam-{role_name}-{self._get_timestamp()}"
            
            # Get default branch SHA
            default_branch = self._get_default_branch(repo)
            base_sha = self._get_branch_sha(repo, default_branch)
            
            # Create branch
            self._create_branch(repo, branch_name, base_sha)
            
            # Create file with remediation content
            file_content = self._generate_remediation_file(role_arn, unused_permissions, remediation_data)
            file_path = f"remediations/{role_name}_remediation.md"
            
            self._create_or_update_file(repo, branch_name, file_path, file_content, 
                                        f"Remediate unused permissions in {role_name}")
            
            # Create pull request
            pr_result = self._create_pull_request(
                repo=repo,
                title=f"Remediate unused permissions in {role_name}",
                body=self._generate_pr_description(role_arn, unused_permissions, remediation_data),
                head=branch_name,
                base=default_branch
            )
            
            return pr_result
            
        except Exception as e:
            logger.error(f"Error creating GitHub PR: {str(e)}", exc_info=True)
            return {"success": False, "error": str(e)}

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
        """
        try:
            if not self.iac_repository:
                return {"success": False, "error": "No repository configured"}
            
            logger.info(f"Creating GitHub issue for role: {role_arn}")
            
            role_name = role_arn.split("/")[-1]
            
            issue_result = self._create_issue(
                repo=self.iac_repository,
                title=f"Import manually-created role into IaC: {role_name}",
                body=self._generate_issue_description(role_arn, unused_permissions, 
                                                       remediation_data, created_by, created_at),
                labels=["security", "iam-remediation", "manual-role"]
            )
            
            return issue_result
            
        except Exception as e:
            logger.error(f"Error creating GitHub issue: {str(e)}", exc_info=True)
            return {"success": False, "error": str(e)}

    def create_unused_role_issue(
        self,
        role_arn: str,
        remediation_data: Dict[str, Any],
        created_by: str = "Unknown",
        created_at: str = "Unknown"
    ) -> Dict[str, Any]:
        """
        Create a GitHub issue for a completely unused IAM role.
        Recommends soft-disable → monitor → delete workflow.
        """
        try:
            if not self.iac_repository:
                return {"success": False, "error": "No repository configured"}

            role_name = role_arn.split("/")[-1]
            logger.info(f"Creating GitHub issue for unused role: {role_name}")

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

            # Generate cleanup commands
            if inline:
                cleanup_cmds = "\n".join(
                    f"aws iam delete-role-policy --role-name {role_name} --policy-name {p}"
                    for p in inline
                )
            else:
                cleanup_cmds = "# No inline policies to remove"

            if attached:
                detach_cmds = "\n".join(
                    f"aws iam detach-role-policy --role-name {role_name} --policy-arn $(aws iam list-attached-role-policies --role-name {role_name} --query \"AttachedPolicies[?PolicyName=='{p}'].PolicyArn\" --output text)"
                    for p in attached
                )
            else:
                detach_cmds = "# No managed policies to detach"

            body = f"""## ⚠️ Unused IAM Role Detected

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
Attach a deny-all inline policy to prevent usage without deleting:

```bash
aws iam put-role-policy \\
    --role-name {role_name} \\
    --policy-name DenyAll-SoftDisable \\
    --policy-document '{deny_policy}'
```

#### Phase 2: Monitor (7–14 days)
Check CloudTrail for any AssumeRole attempts:

```bash
aws cloudtrail lookup-events \\
    --lookup-attributes AttributeKey=ResourceName,AttributeValue={role_name} \\
    --start-time $(date -u -v-14d +%Y-%m-%dT%H:%M:%SZ) \\
    --region us-east-1
```

#### Phase 3: Delete (After monitoring period)
```bash
# Remove inline policies
{cleanup_cmds}

# Detach managed policies
{detach_cmds}

# Delete the role
aws iam delete-role --role-name {role_name}
```

---
*Generated by IAM Permission Remediation Solution*
*Finding type: UnusedIAMRole*
"""

            issue_result = self._create_issue(
                repo=self.iac_repository,
                title=f"🗑️ Unused IAM Role: {role_name}",
                body=body,
                labels=["security", "iam-remediation", "unused-role"]
            )

            return issue_result

        except Exception as e:
            logger.error(f"Error creating unused role issue: {str(e)}", exc_info=True)
            return {"success": False, "error": str(e)}

    def _get_default_branch(self, repo: str) -> str:
        """Get the default branch name for a repository"""
        try:
            url = f"{self.base_url}/repos/{repo}"
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            return response.json().get("default_branch", "main")
        except Exception as e:
            logger.warning(f"Could not get default branch, using 'main': {e}")
            return "main"

    def _get_branch_sha(self, repo: str, branch: str) -> str:
        """Get the SHA of a branch"""
        url = f"{self.base_url}/repos/{repo}/git/ref/heads/{branch}"
        response = requests.get(url, headers=self.headers, timeout=30)
        response.raise_for_status()
        return response.json()["object"]["sha"]

    def _create_branch(self, repo: str, branch_name: str, sha: str) -> None:
        """Create a new branch"""
        url = f"{self.base_url}/repos/{repo}/git/refs"
        data = {
            "ref": f"refs/heads/{branch_name}",
            "sha": sha
        }
        response = requests.post(url, json=data, headers=self.headers, timeout=30)
        response.raise_for_status()
        logger.info(f"Created branch: {branch_name}")

    def _create_or_update_file(self, repo: str, branch: str, path: str, 
                                content: str, message: str) -> None:
        """Create or update a file in the repository"""
        url = f"{self.base_url}/repos/{repo}/contents/{path}"
        
        # Check if file exists
        sha = None
        try:
            response = requests.get(url, headers=self.headers, params={"ref": branch}, timeout=30)
            if response.status_code == 200:
                sha = response.json().get("sha")
        except requests.RequestException:
            pass
        
        data = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch
        }
        if sha:
            data["sha"] = sha
        
        response = requests.put(url, json=data, headers=self.headers, timeout=30)
        response.raise_for_status()
        logger.info(f"Created/updated file: {path}")

    def _create_pull_request(self, repo: str, title: str, body: str, 
                             head: str, base: str) -> Dict[str, Any]:
        """Create a pull request"""
        url = f"{self.base_url}/repos/{repo}/pulls"
        data = {
            "title": title,
            "body": body,
            "head": head,
            "base": base
        }
        response = requests.post(url, json=data, headers=self.headers, timeout=30)
        response.raise_for_status()
        result = response.json()
        return {
            "success": True,
            "pr_url": result.get("html_url"),
            "pr_number": result.get("number")
        }

    def _create_issue(self, repo: str, title: str, body: str, 
                      labels: List[str]) -> Dict[str, Any]:
        """Create an issue"""
        url = f"{self.base_url}/repos/{repo}/issues"
        data = {
            "title": title,
            "body": body,
            "labels": labels
        }
        response = requests.post(url, json=data, headers=self.headers, timeout=30)
        response.raise_for_status()
        result = response.json()
        return {
            "success": True,
            "issue_url": result.get("html_url"),
            "issue_number": result.get("number")
        }

    def _generate_remediation_file(self, role_arn: str, unused_permissions: List[str],
                                    remediation_data: Dict[str, Any]) -> str:
        """Generate remediation file content"""
        role_name = role_arn.split("/")[-1]
        perms_list = "\n".join(f"- `{p}`" for p in unused_permissions[:50])
        if len(unused_permissions) > 50:
            perms_list += f"\n- ... and {len(unused_permissions) - 50} more"
        
        return f"""# IAM Permission Remediation: {role_name}

## Role Information
- **ARN:** `{role_arn}`
- **Unused Permissions Count:** {len(unused_permissions)}

## Unused Permissions
{perms_list}

## Recommended Policy Changes
```json
{remediation_data.get('updated_policy', 'See policy diff below')}
```

## Policy Diff
```diff
{remediation_data.get('policy_diff', 'No diff available')}
```

## Notes
- These permissions have not been used in the last 90 days
- Review carefully before applying changes
- Generated by IAM Permission Remediation Solution
"""

    def _generate_pr_description(self, role_arn: str, unused_permissions: List[str],
                                  remediation_data: Dict[str, Any]) -> str:
        """Generate PR description"""
        perms_sample = unused_permissions[:20]
        perms_list = "\n".join(f"- `{p}`" for p in perms_sample)
        if len(unused_permissions) > 20:
            perms_list += f"\n- ... and {len(unused_permissions) - 20} more"
        
        return f"""## IAM Permission Remediation

**Role:** `{role_arn}`
**Unused Permissions:** {len(unused_permissions)}

### Summary
{remediation_data.get('policy_summary', 'Removing unused permissions to improve security posture.')}

### Unused Permissions (sample)
{perms_list}

### Context
- Permissions identified by AWS IAM Access Analyzer
- Not used in the last 90 days
- Please review before merging

---
*Generated by IAM Permission Remediation Solution*
"""

    def _generate_issue_description(self, role_arn: str, unused_permissions: List[str],
                                     remediation_data: Dict[str, Any],
                                     created_by: str, created_at: str) -> str:
        """Generate issue description"""
        perms_sample = unused_permissions[:20]
        perms_list = "\n".join(f"- `{p}`" for p in perms_sample)
        if len(unused_permissions) > 20:
            perms_list += f"\n- ... and {len(unused_permissions) - 20} more"
        
        return f"""## Import Manually-Created Role into IaC

### Role Information
- **ARN:** `{role_arn}`
- **Created By:** {created_by}
- **Created At:** {created_at}
- **Unused Permissions:** {len(unused_permissions)}

### Unused Permissions (sample)
{perms_list}

### Recommended Action
Import this role into Infrastructure as Code to enable:
- Version control for IAM policies
- Automated remediation of future findings
- Consistent configuration across environments

### Import Guidance
{remediation_data.get('import_guidance', 'See remediation data for CDK/CloudFormation templates.')}

---
*Generated by IAM Permission Remediation Solution*
"""

    def _get_timestamp(self) -> str:
        """Get timestamp for branch naming"""
        return datetime.utcnow().strftime("%Y%m%d%H%M%S")
