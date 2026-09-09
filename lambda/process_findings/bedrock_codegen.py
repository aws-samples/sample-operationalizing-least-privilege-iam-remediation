"""
Amazon Bedrock Code Generation and Explanation

Uses Amazon Bedrock (Claude) to:
1. Generate production-ready AWS Cloud Development Kit (AWS CDK) code from IAM Access Analyzer recommendations
2. Generate plain-English explanations of policy changes

Note: The recommended policy comes from IAM Access Analyzer's 
generate-finding-recommendation API. Amazon Bedrock's role is to convert
that policy to CDK code and explain the changes in human-readable terms.
"""

import logging
import json
import os
import boto3
from typing import Dict, Any, List

logger = logging.getLogger()


class BedrockCodeGenerator:
    """Generates CDK code and explanations using Amazon Bedrock"""

    def __init__(self):
        # Amazon Bedrock runtime client (the bedrock-runtime API serves model invocations).
        self.bedrock_client = boto3.client("bedrock-runtime")
        # Model IDs are configurable via environment variables so they can be updated
        # (e.g., when a model is deprecated) without code changes. Defaults are current
        # Anthropic Claude models on Amazon Bedrock, referenced by cross-region inference
        # profile IDs. `os.environ.get(...) or default` handles both unset and empty values.
        self.model_id = os.environ.get("BEDROCK_CODEGEN_MODEL") or "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        # Use a faster/cheaper model for explanations
        self.explanation_model_id = os.environ.get("BEDROCK_EXPLANATION_MODEL") or "us.anthropic.claude-haiku-4-5-20251001-v1:0"

    def generate_cdk_code(
        self,
        role_name: str,
        current_policy: Dict[str, Any],
        recommended_policy: Dict[str, Any],
        unused_permissions: List[str]
    ) -> Dict[str, Any]:
        """
        Generate CDK code for role remediation using Amazon Bedrock.
        
        The recommended_policy comes from IAM Access Analyzer - we're converting
        it to CDK code, not generating the policy ourselves.
        
        Args:
            role_name: Name of the IAM role
            current_policy: Current IAM policy (for context)
            recommended_policy: Access Analyzer's recommended policy
            unused_permissions: List of permissions being removed (for context)
            
        Returns:
            Dictionary with:
            - code: Generated CDK code
            - validation_passed: Whether code passed validation
        """
        try:
            logger.info(f"Generating CDK code for role: {role_name}")
            
            prompt = self._create_cdk_prompt(
                role_name,
                current_policy,
                recommended_policy,
                unused_permissions
            )
            
            response = self.bedrock_client.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 2048,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                })
            )
            
            response_body = json.loads(response["body"].read())
            generated_code = response_body["content"][0]["text"]
            
            # Validate generated code
            validation_result = self._validate_code(generated_code)
            
            return {
                "code": self._extract_code(generated_code),
                "validation_passed": validation_result["passed"],
                "validation_errors": validation_result.get("errors", [])
            }
            
        except Exception as e:
            logger.error(f"Error generating CDK code: {str(e)}", exc_info=True)
            return {
                "code": "",
                "validation_passed": False,
                "validation_errors": [str(e)]
            }

    def generate_policy_explanation(
        self,
        role_name: str,
        unused_permissions: List[str],
        current_policy: Dict[str, Any],
        recommended_policy: Dict[str, Any]
    ) -> str:
        """
        Generate a plain-English explanation of policy changes using Amazon Bedrock.
        
        This helps reviewers quickly understand what permissions are being
        removed and why, without having to parse policy JSON.
        
        Examples of good explanations:
        - "This change removes write access to S3, keeping only read and list permissions."
        - "This removes unused DynamoDB delete operations while preserving query and scan access."
        - "This removes all EC2 permissions since the role only needs Lambda access."
        
        Args:
            role_name: Name of the role
            unused_permissions: Permissions being removed
            current_policy: Current policy (for context)
            recommended_policy: Access Analyzer's recommended policy
            
        Returns:
            Human-readable explanation of the changes
        """
        try:
            prompt = f"""You are an AWS security expert. Provide a clear, concise explanation of IAM policy changes.

Role: {role_name}

Permissions being removed:
{chr(10).join(f"- {perm}" for perm in unused_permissions[:20])}
{f"... and {len(unused_permissions) - 20} more" if len(unused_permissions) > 20 else ""}

Current policy statement count: {len(current_policy.get('Statement', []))}
Recommended policy statement count: {len(recommended_policy.get('Statement', []))}

Write a 2-3 sentence explanation that:
1. Summarizes what access is being removed (e.g., "write access to S3", "delete operations on DynamoDB")
2. Clarifies what access remains (e.g., "read and list permissions are preserved")
3. Explains the security benefit in plain terms

Be specific about AWS services and action types (read/write/delete/admin).
Do NOT use technical jargon or policy syntax.
Do NOT start with "This change" - vary your sentence structure.

Example good responses:
- "The role currently has full S3 access but only uses read operations. Removing s3:PutObject, s3:DeleteObject, and s3:PutBucketPolicy reduces the scope of impact if credentials are compromised, while preserving the s3:GetObject and s3:ListBucket permissions the application needs."
- "Unused EC2 instance management permissions (RunInstances, TerminateInstances, StopInstances) are being removed. The role retains its Lambda and CloudWatch access, which are actively used. This prevents potential unauthorized compute resource creation."

Write the explanation now:"""
            
            response = self.bedrock_client.invoke_model(
                modelId=self.explanation_model_id,  # Use Haiku for speed
                contentType="application/json",
                accept="application/json",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 300,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                })
            )
            
            response_body = json.loads(response["body"].read())
            return response_body["content"][0]["text"].strip()
            
        except Exception as e:
            logger.error(f"Error generating policy explanation: {str(e)}")
            # Fallback to basic explanation
            return f"Removing {len(unused_permissions)} unused permission(s) from {role_name} to reduce security risk."

    def _create_cdk_prompt(
        self,
        role_name: str,
        current_policy: Dict[str, Any],
        recommended_policy: Dict[str, Any],
        unused_permissions: List[str]
    ) -> str:
        """Create the prompt for CDK code generation"""
        
        return f"""You are an AWS CDK expert. Generate production-ready Python CDK code to implement the recommended IAM policy.

Role Name: {role_name}

IMPORTANT: The recommended policy below comes from IAM Access Analyzer. Your job is to convert it to CDK code, not to modify it.

Recommended Policy (from IAM Access Analyzer):
```json
{json.dumps(recommended_policy, indent=2)}
```

Permissions being removed from current policy:
{chr(10).join(f"- {perm}" for perm in unused_permissions[:15])}

Requirements:
1. Generate Python CDK code that creates/updates the role with the RECOMMENDED policy exactly as provided
2. Include proper imports (aws_cdk, aws_iam)
3. Use CDK best practices (PolicyStatement, proper resource ARNs)
4. Add a comment noting this is a remediated policy from Access Analyzer
5. Include tags: ManagedBy=CDK, RemediatedBy=AccessAnalyzer

Output ONLY the Python code block, no explanations:

```python
"""
        
    def _extract_code(self, response: str) -> str:
        """Extract Python code from Amazon Bedrock response"""
        try:
            if "```python" in response:
                code = response.split("```python")[1].split("```")[0]
                return code.strip()
            elif "```" in response:
                code = response.split("```")[1].split("```")[0]
                return code.strip()
            return response.strip()
        except Exception as e:
            logger.warning(f"Error extracting code: {str(e)}")
            return response

    def _validate_code(self, code: str) -> Dict[str, Any]:
        """
        Validate generated CDK code
        
        Args:
            code: Generated Python code
            
        Returns:
            Validation result with passed status and any errors
        """
        try:
            # Extract code if wrapped in markdown
            clean_code = self._extract_code(code)
            
            # Basic syntax validation
            compile(clean_code, "<string>", "exec")
            
            # Check for required CDK imports/patterns
            required_patterns = ["iam", "PolicyStatement"]
            
            missing_patterns = [
                pattern for pattern in required_patterns
                if pattern not in clean_code
            ]
            
            if missing_patterns:
                return {
                    "passed": False,
                    "errors": [f"Missing required pattern: {pattern}" for pattern in missing_patterns]
                }
            
            logger.info("CDK code validation passed")
            return {"passed": True, "errors": []}
            
        except SyntaxError as e:
            logger.error(f"Syntax error in generated code: {str(e)}")
            return {"passed": False, "errors": [f"Syntax error: {str(e)}"]}
        except Exception as e:
            logger.error(f"Error validating code: {str(e)}")
            return {"passed": False, "errors": [str(e)]}
