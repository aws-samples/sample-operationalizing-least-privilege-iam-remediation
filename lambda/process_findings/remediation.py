"""
Remediation Generator

Generates remediation data (policy diffs, code changes) for both IaC and manual roles.
Uses IAM Access Analyzer recommendations for the updated policy.
Uses Amazon Bedrock to generate AWS Cloud Development Kit (AWS CDK) code and plain-English explanations.
"""

import logging
import boto3
import json
from typing import Dict, Any, List, Optional
from difflib import unified_diff
from bedrock_codegen import BedrockCodeGenerator

logger = logging.getLogger()


class RemediationGenerator:
    """Generates remediation data for IAM roles"""

    def __init__(self):
        self.iam_client = boto3.client("iam")
        self.bedrock = BedrockCodeGenerator()

    def generate_iac_remediation(
        self,
        role_arn: str,
        finding: Dict[str, Any],
        role_origin: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate remediation for IaC-managed roles
        
        Uses Access Analyzer's recommended policy and Amazon Bedrock for CDK code generation.
        
        Args:
            role_arn: ARN of the IAM role
            finding: Finding dict with 'details' and 'recommendation' from Access Analyzer
            role_origin: Information about how the role was created (stack, repo, etc.)
        
        Returns:
            Dictionary with:
            - cdk_code: Amazon Bedrock-generated CDK code
            - policy_diff: Human-readable policy diff
            - explanation: Plain-English explanation of changes
            - context: Additional context for reviewers
        """
        try:
            logger.info(f"Generating IaC remediation for role: {role_arn}")
            
            role_name = role_arn.split("/")[-1]
            
            # Get current role policy
            current_policy = self._get_role_policy(role_name)
            
            # Get recommended policy from Access Analyzer
            recommendation = finding.get("recommendation", {})
            if recommendation.get("status") != "SUCCEEDED":
                logger.warning(f"No valid recommendation for {role_name}, skipping")
                return None
            
            recommended_policy = recommendation.get("recommendedPolicy", {})
            if not recommended_policy:
                logger.warning(f"Empty recommended policy for {role_name}")
                return None
            
            # Extract unused permissions from finding details
            unused_permissions = self._extract_unused_permissions(finding.get("details", {}))
            
            # Generate policy diff
            policy_diff = self._generate_policy_diff(current_policy, recommended_policy)
            
            # Use Amazon Bedrock to generate CDK code from the Access Analyzer recommendation
            logger.info("Calling Amazon Bedrock to generate CDK code")
            bedrock_result = self.bedrock.generate_cdk_code(
                role_name,
                current_policy,
                recommended_policy,  # Use Access Analyzer's recommendation
                unused_permissions
            )
            
            # Generate plain-English explanation using Amazon Bedrock
            explanation = self.bedrock.generate_policy_explanation(
                role_name,
                unused_permissions,
                current_policy,
                recommended_policy
            )
            
            return {
                "type": "iac",
                "role_name": role_name,
                "role_arn": role_arn,
                "cdk_code": bedrock_result.get("code", ""),
                "cdk_validation_passed": bedrock_result.get("validation_passed", False),
                "policy_diff": policy_diff,
                "explanation": explanation,
                "recommended_policy": recommended_policy,
                "unused_permissions": unused_permissions,
                "context": {
                    "stack_name": role_origin.get("stack_name"),
                    "repository": role_origin.get("repository"),
                    "recommendation_source": "IAM Access Analyzer",
                    "reason": "Permissions have not been used within the analysis period"
                }
            }
            
        except Exception as e:
            logger.error(f"Error generating IaC remediation: {str(e)}", exc_info=True)
            return None

    def generate_manual_remediation(
        self,
        role_arn: str,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate remediation for manually-created roles
        
        Provides the Access Analyzer recommended policy directly, plus a
        plain-English explanation and IaC import guidance.
        
        Args:
            role_arn: ARN of the IAM role
            finding: Finding dict with 'details' and 'recommendation' from Access Analyzer
        
        Returns:
            Dictionary with:
            - recommended_policy: Access Analyzer's recommended policy
            - policy_diff: Human-readable policy diff
            - explanation: Plain-English explanation of changes
            - import_guidance: Steps to import into IaC
        """
        try:
            logger.info(f"Generating manual remediation for role: {role_arn}")
            
            role_name = role_arn.split("/")[-1]
            
            # Get current role policy
            current_policy = self._get_role_policy(role_name)
            
            # Get recommended policy from Access Analyzer
            recommendation = finding.get("recommendation", {})
            if recommendation.get("status") != "SUCCEEDED":
                logger.warning(f"No valid recommendation for {role_name}, skipping")
                return None
            
            recommended_policy = recommendation.get("recommendedPolicy", {})
            if not recommended_policy:
                logger.warning(f"Empty recommended policy for {role_name}")
                return None
            
            # Extract unused permissions from finding details
            unused_permissions = self._extract_unused_permissions(finding.get("details", {}))
            
            # Generate policy diff
            policy_diff = self._generate_policy_diff(current_policy, recommended_policy)
            
            # Generate plain-English explanation using Amazon Bedrock
            explanation = self.bedrock.generate_policy_explanation(
                role_name,
                unused_permissions,
                current_policy,
                recommended_policy
            )
            
            # Generate import guidance
            import_guidance = self._generate_import_guidance(role_name, recommended_policy)
            
            return {
                "type": "manual",
                "role_name": role_name,
                "role_arn": role_arn,
                "recommended_policy": recommended_policy,
                "policy_diff": policy_diff,
                "explanation": explanation,
                "unused_permissions": unused_permissions,
                "import_guidance": import_guidance,
                "context": {
                    "recommendation_source": "IAM Access Analyzer",
                    "reason": "Permissions have not been used within the analysis period",
                    "next_steps": "Apply the recommended policy or import this role into IaC"
                }
            }
            
        except Exception as e:
            logger.error(f"Error generating manual remediation: {str(e)}", exc_info=True)
            return None

    def _extract_unused_permissions(self, finding_details: Dict[str, Any]) -> List[str]:
        """Extract list of unused permissions from finding details"""
        unused = []
        try:
            # The finding details contain information about unused actions
            finding_type = finding_details.get("findingType")
            if finding_type == "UnusedPermission":
                # Extract from the finding's unused permission details
                for detail in finding_details.get("findingDetails", []):
                    if "unusedPermissionDetails" in detail:
                        actions = detail["unusedPermissionDetails"].get("actions", [])
                        unused.extend([a.get("action") for a in actions if a.get("action")])
        except Exception as e:
            logger.warning(f"Error extracting unused permissions: {str(e)}")
        return unused

    def _get_role_policy(self, role_name: str) -> Dict[str, Any]:
        """Get the current inline policy for a role"""
        try:
            # Get inline policies
            response = self.iam_client.list_role_policies(RoleName=role_name)
            policy_names = response.get("PolicyNames", [])
            
            if not policy_names:
                # Check for attached managed policies
                attached = self.iam_client.list_attached_role_policies(RoleName=role_name)
                if attached.get("AttachedPolicies"):
                    # Get the first attached policy
                    policy_arn = attached["AttachedPolicies"][0]["PolicyArn"]
                    policy = self.iam_client.get_policy(PolicyArn=policy_arn)
                    version_id = policy["Policy"]["DefaultVersionId"]
                    policy_version = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id
                    )
                    return policy_version.get("PolicyVersion", {}).get("Document", {})
                
                logger.warning(f"No policies found for role: {role_name}")
                return {"Version": "2012-10-17", "Statement": []}
            
            # Get the first inline policy
            policy_name = policy_names[0]
            policy_response = self.iam_client.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
            
            return policy_response.get("PolicyDocument", {})
            
        except Exception as e:
            logger.error(f"Error getting role policy: {str(e)}", exc_info=True)
            return {"Version": "2012-10-17", "Statement": []}

    def _generate_policy_diff(
        self,
        current_policy: Dict[str, Any],
        recommended_policy: Dict[str, Any]
    ) -> str:
        """
        Generate human-readable diff between policies
        
        Args:
            current_policy: Current policy
            recommended_policy: Access Analyzer recommended policy
            
        Returns:
            Unified diff string
        """
        try:
            current_str = json.dumps(current_policy, indent=2, sort_keys=True).splitlines()
            recommended_str = json.dumps(recommended_policy, indent=2, sort_keys=True).splitlines()
            
            diff = unified_diff(
                current_str,
                recommended_str,
                fromfile="current_policy.json",
                tofile="recommended_policy.json",
                lineterm=""
            )
            
            return "\n".join(diff)
            
        except Exception as e:
            logger.error(f"Error generating policy diff: {str(e)}", exc_info=True)
            return ""

    def _generate_import_guidance(self, role_name: str, recommended_policy: Dict[str, Any]) -> str:
        """Generate guidance for importing manual role into IaC"""
        
        policy_json = json.dumps(recommended_policy, indent=2)
        
        guidance = f"""
## Import {role_name} into Infrastructure-as-Code

### Option 1: Apply Recommended Policy Immediately
You can apply the Access Analyzer recommended policy directly:

```bash
# Save the recommended policy
cat > recommended_policy.json << 'EOF'
{policy_json}
EOF

# Apply to the role (replace <policy-name> with actual policy name)
aws iam put-role-policy \\
    --role-name {role_name} \\
    --policy-name <policy-name> \\
    --policy-document file://recommended_policy.json
```

### Option 2: Import into CDK (Recommended for Long-term)

#### Step 1: Export Current Configuration
```bash
aws iam get-role --role-name {role_name} > {role_name}_role.json
aws iam list-role-policies --role-name {role_name}
```

#### Step 2: Create CDK Definition
Add to your CDK stack:

```python
from aws_cdk import aws_iam as iam

# Import existing role or create new one with recommended policy
role = iam.Role(self, "{role_name}",
    role_name="{role_name}",
    assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),  # Adjust as needed
    description="Imported from manual creation - remediated"
)

# Add the recommended (right-sized) policy
role.add_to_policy(iam.PolicyStatement(
    # Add statements from recommended policy
))
```

#### Step 3: Deploy and Verify
```bash
cdk deploy
aws iam get-role --role-name {role_name}
```

### Benefits of IaC Management
- Version control for all permission changes
- Code review process for security updates
- Consistent deployment across environments
- Automated remediation for future findings
- Audit trail of who changed what and when
"""
        return guidance.strip()

    def generate_unused_role_remediation(
        self,
        role_arn: str,
        finding: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Generate remediation for completely unused IAM roles.

        Recommends a phased approach:
        1. Soft-disable: attach a deny-all inline policy
        2. Monitor for breakage
        3. Delete the role if no issues arise

        Args:
            role_arn: ARN of the unused IAM role
            finding: Finding dict with 'details' from Access Analyzer

        Returns:
            Dictionary with remediation guidance for unused role
        """
        try:
            role_name = role_arn.split("/")[-1]
            logger.info(f"Generating unused role remediation for: {role_name}")

            # Get role metadata
            role_info = self._get_role_info(role_name)

            # Get attached policies for context
            attached_policies = self._get_attached_policies(role_name)
            inline_policies = self._get_inline_policy_names(role_name)

            finding_details = finding.get("details", {})
            created_at = finding_details.get("createdAt", "Unknown")
            analyzed_at = finding_details.get("analyzedAt", "Unknown")

            # SECURITY NOTE: Wildcards with the Deny effect are safe and intentional for
            # soft-disable purposes. Unlike Allow wildcards (which grant everything), a
            # Deny "*" on "*" blocks all actions without modifying trust or attached
            # policies, providing a reversible disable mechanism. To restore access,
            # remove this inline policy with delete-role-policy.
            deny_all_policy = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "DenyAllSoftDisable",
                    "Effect": "Deny",
                    "Action": "*",  # Deny all actions (safe with Deny effect)
                    "Resource": "*"  # On all resources (safe with Deny effect)
                }]
            }, indent=2)

            return {
                "type": "unused_role",
                "role_name": role_name,
                "role_arn": role_arn,
                "unused_permissions": [],  # Entire role is unused
                "role_info": role_info,
                "attached_policies": attached_policies,
                "inline_policies": inline_policies,
                "deny_all_policy": deny_all_policy,
                "finding_created_at": str(created_at),
                "analyzed_at": str(analyzed_at),
                "context": {
                    "recommendation_source": "IAM Access Analyzer",
                    "finding_type": "UnusedIAMRole",
                    "reason": "This role has not been assumed within the analysis period"
                }
            }

        except Exception as e:
            logger.error(f"Error generating unused role remediation: {str(e)}", exc_info=True)
            return None

    def _get_role_info(self, role_name: str) -> Dict[str, Any]:
        """Get basic role metadata"""
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            role = response.get("Role", {})
            trust_policy = role.get("AssumeRolePolicyDocument", {})
            # Extract service principals from trust policy
            principals = []
            for stmt in trust_policy.get("Statement", []):
                principal = stmt.get("Principal", {})
                if isinstance(principal, dict):
                    svc = principal.get("Service", [])
                    if isinstance(svc, str):
                        principals.append(svc)
                    elif isinstance(svc, list):
                        principals.extend(svc)
            return {
                "create_date": str(role.get("CreateDate", "Unknown")),
                "description": role.get("Description", ""),
                "trust_principals": principals,
                "path": role.get("Path", "/"),
                "tags": {t["Key"]: t["Value"] for t in role.get("Tags", [])}
            }
        except Exception as e:
            logger.warning(f"Error getting role info for {role_name}: {str(e)}")
            return {}

    def _get_attached_policies(self, role_name: str) -> List[str]:
        """Get list of attached managed policy names"""
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            return [p["PolicyName"] for p in response.get("AttachedPolicies", [])]
        except Exception as e:
            logger.warning(f"Error getting attached policies for {role_name}: {str(e)}")
            return []

    def _get_inline_policy_names(self, role_name: str) -> List[str]:
        """Get list of inline policy names"""
        try:
            response = self.iam_client.list_role_policies(RoleName=role_name)
            return response.get("PolicyNames", [])
        except Exception as e:
            logger.warning(f"Error getting inline policies for {role_name}: {str(e)}")
            return []

