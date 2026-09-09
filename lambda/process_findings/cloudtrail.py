"""
CloudTrail Integration - Role Attribution

Queries AWS CloudTrail to determine if a role was created via IaC or manually.
"""

import logging
import os
import boto3
import json
from typing import Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger()


class CloudTrailClient:
    """Client for CloudTrail API"""

    def __init__(self):
        self.client = boto3.client("cloudtrail")
        self.iam_client = boto3.client("iam")

    def get_role_origin(self, role_arn: str, account_id: str = None) -> Dict[str, Any]:
        """
        Determine if a role was created via IaC or manually
        
        Args:
            role_arn: ARN of the IAM role
            account_id: AWS account ID where the role lives (for cross-account org findings)
            
        Returns:
            Dictionary with role origin information:
            {
                "type": "iac" or "manual" or "unknown",
                "account_id": "123456789012",
                "repository": "org/repo" (for IaC),
                "stack_name": "stack-name" (for IaC),
                "created_by": "user@example.com" (for manual),
                "created_at": "2024-01-01T00:00:00Z" (for manual)
            }
        """
        try:
            role_name = role_arn.split("/")[-1]
            lambda_account = boto3.client("sts").get_caller_identity()["Account"]
            target_account = account_id or lambda_account
            logger.info(f"Determining origin for role: {role_name} in account {target_account}")

            # For cross-account roles, we may not be able to query IAM/CloudTrail directly
            if target_account != lambda_account:
                logger.info(f"Cross-account role detected (Lambda in {lambda_account}, role in {target_account})")
                return self._get_cross_account_origin(role_arn, role_name, target_account)
            
            # Get role creation time
            role = self.iam_client.get_role(RoleName=role_name)
            create_date = role["Role"]["CreateDate"]
            
            # Query CloudTrail for role creation event
            # Look back 90 days from creation date
            start_time = create_date - timedelta(days=1)
            end_time = create_date + timedelta(days=1)
            
            response = self.client.lookup_events(
                LookupAttributes=[
                    {
                        "AttributeKey": "ResourceName",
                        "AttributeValue": role_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50
            )
            
            events = response.get("Events", [])
            
            # Filter for CreateRole events
            create_role_events = [
                e for e in events 
                if e.get("EventName") == "CreateRole"
            ]
            
            if not create_role_events:
                logger.warning(f"No CreateRole CloudTrail events found for role: {role_name}")
                return {
                    "type": "unknown",
                    "created_at": create_date.isoformat()
                }
            
            # Analyze the creation event
            creation_event = create_role_events[0]
            user_identity = creation_event.get("UserIdentity", {})
            principal_id = user_identity.get("principalId", "")
            user_agent = creation_event.get("UserAgent", "")
            
            # Check if created via CloudFormation or CDK
            if "cloudformation" in user_agent.lower() or \
               "cloudformation.amazonaws.com" in principal_id:
                return self._extract_iac_origin(creation_event, role_name)
            
            # Check if created via console or API
            if user_identity.get("type") == "IAMUser":
                return {
                    "type": "manual",
                    "created_by": user_identity.get("userName", "unknown"),
                    "created_at": creation_event.get("EventTime", "").isoformat()
                }
            
            # Check if created via federated user
            if user_identity.get("type") == "FederatedUser":
                return {
                    "type": "manual",
                    "created_by": user_identity.get("federatedUser", {}).get("arn", "unknown"),
                    "created_at": creation_event.get("EventTime", "").isoformat()
                }
            
            # Default to manual if we can't determine
            return {
                "type": "manual",
                "created_by": principal_id,
                "created_at": creation_event.get("EventTime", "").isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error determining role origin: {str(e)}", exc_info=True)
            return {
                "type": "unknown",
                "account_id": account_id,
                "error": str(e)
            }

    def _get_cross_account_origin(self, role_arn: str, role_name: str, account_id: str) -> Dict[str, Any]:
        """
        Attempt to determine role origin for a role in a different account.

        Tries to use an org CloudTrail trail first. If that fails, returns
        unknown with the account ID so the issue still gets created.

        Args:
            role_arn: ARN of the role
            role_name: Name of the role
            account_id: Account where the role lives

        Returns:
            Role origin dict with account_id included
        """
        try:
            cross_account_role = os.environ.get("CROSS_ACCOUNT_ROLE_NAME", "OrganizationAccountAccessRole")
            sts = boto3.client("sts")
            assumed = sts.assume_role(
                RoleArn=f"arn:aws:iam::{account_id}:role/{cross_account_role}",
                RoleSessionName="remediation-attribution"
            )
            creds = assumed["Credentials"]
            remote_ct = boto3.client(
                "cloudtrail",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            remote_iam = boto3.client(
                "iam",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )

            role = remote_iam.get_role(RoleName=role_name)
            create_date = role["Role"]["CreateDate"]
            start_time = create_date - timedelta(days=1)
            end_time = create_date + timedelta(days=1)

            response = remote_ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": role_name}],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            )
            create_events = [e for e in response.get("Events", []) if e.get("EventName") == "CreateRole"]

            if not create_events:
                logger.warning(f"No CreateRole events found for {role_name} in account {account_id}")
                return {"type": "unknown", "account_id": account_id, "created_at": create_date.isoformat()}

            event = create_events[0]
            user_agent = event.get("UserAgent", "")
            if "cloudformation" in user_agent.lower():
                origin = self._extract_iac_origin(event, role_name)
                origin["account_id"] = account_id
                return origin

            user_identity = event.get("UserIdentity", {})
            return {
                "type": "manual",
                "account_id": account_id,
                "created_by": user_identity.get("userName", user_identity.get("principalId", "unknown")),
                "created_at": event.get("EventTime", "").isoformat() if hasattr(event.get("EventTime", ""), "isoformat") else str(event.get("EventTime", "")),
            }

        except Exception as e:
            logger.warning(f"Cross-account attribution failed for {role_name} in {account_id}: {str(e)}")
            return {
                "type": "unknown",
                "account_id": account_id,
                "error": str(e)
            }

    def _extract_iac_origin(self, event: Dict[str, Any], role_name: str) -> Dict[str, Any]:
        """
        Extract IaC origin information from CloudTrail event
        
        Args:
            event: CloudTrail event
            role_name: Name of the role
            
        Returns:
            Dictionary with IaC origin information
        """
        try:
            cloud_trail_event = json.loads(event.get("CloudTrailEvent", "{}"))
            request_params = cloud_trail_event.get("requestParameters", {})
            
            # Extract stack name from CloudFormation event
            stack_name = request_params.get("stackName", "unknown")
            
            # Try to extract repository from tags or other metadata
            # This is a simplified approach - in production, you might store
            # repository information in role tags
            repository = self._get_repository_from_tags(role_name)
            
            return {
                "type": "iac",
                "stack_name": stack_name,
                "repository": repository,
                "created_at": event.get("EventTime", "").isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error extracting IaC origin: {str(e)}", exc_info=True)
            return {
                "type": "iac",
                "stack_name": "unknown",
                "repository": "unknown"
            }

    def _get_repository_from_tags(self, role_name: str) -> str:
        """
        Get repository information from role tags
        
        In production, you would store the repository URL or name
        in a tag on the role when it's created via IaC.
        
        Args:
            role_name: Name of the role
            
        Returns:
            Repository identifier
        """
        try:
            role = self.iam_client.get_role(RoleName=role_name)
            tags = role.get("Role", {}).get("Tags", [])
            
            for tag in tags:
                if tag.get("Key") == "Repository":
                    return tag.get("Value", "unknown")
            
            return "unknown"
            
        except Exception as e:
            logger.warning(f"Error getting repository from tags: {str(e)}")
            return "unknown"
