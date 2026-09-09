"""
IAM Access Analyzer Integration

Queries AWS Identity and Access Management (IAM) Access Analyzer for unused permission
findings and retrieves policy recommendations using the generate-finding-recommendation API.

Supports both ACCOUNT_UNUSED_ACCESS and ORGANIZATION_UNUSED_ACCESS analyzer types.
When using an org-level analyzer, findings include roles from all member accounts.
"""

import logging
import os
import re
import boto3
import time
from typing import List, Dict, Any, Optional

logger = logging.getLogger()


class AccessAnalyzerClient:
    """Client for IAM Access Analyzer API"""

    def __init__(self):
        self.client = boto3.client("accessanalyzer")
        self.account_id = boto3.client("sts").get_caller_identity()["Account"]
        self._analyzer_arn: Optional[str] = None
        self.analyzer_scope = os.environ.get("ANALYZER_SCOPE", "account")

    @staticmethod
    def extract_account_id(resource_arn: str) -> Optional[str]:
        """Extract AWS account ID from a resource ARN.

        Args:
            resource_arn: e.g. arn:aws:iam::123456789012:role/MyRole

        Returns:
            Account ID string or None
        """
        match = re.match(r"arn:aws:iam::(\d{12}):", resource_arn or "")
        return match.group(1) if match else None

    @property
    def analyzer_arn(self) -> Optional[str]:
        """Get the ARN of the unused access analyzer.

        Checks for ORGANIZATION_UNUSED_ACCESS first when analyzer_scope is
        'organization', then falls back to ACCOUNT_UNUSED_ACCESS.
        """
        if self._analyzer_arn is None:
            if self.analyzer_scope == "organization":
                org_analyzers = self.client.list_analyzers(type="ORGANIZATION_UNUSED_ACCESS")
                if org_analyzers.get("analyzers"):
                    self._analyzer_arn = org_analyzers["analyzers"][0]["arn"]
                    logger.info(f"Using ORGANIZATION_UNUSED_ACCESS analyzer: {self._analyzer_arn}")
                    return self._analyzer_arn
                logger.warning("No ORGANIZATION_UNUSED_ACCESS analyzer found, falling back to account-level")

            acct_analyzers = self.client.list_analyzers(type="ACCOUNT_UNUSED_ACCESS")
            if acct_analyzers.get("analyzers"):
                self._analyzer_arn = acct_analyzers["analyzers"][0]["arn"]
                logger.info(f"Using ACCOUNT_UNUSED_ACCESS analyzer: {self._analyzer_arn}")
        return self._analyzer_arn

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get all unused permission findings from Access Analyzer
        
        Returns:
            List of findings with unused permissions and recommendations
        """
        try:
            logger.info("Querying IAM Access Analyzer for unused access findings")
            
            if not self.analyzer_arn:
                logger.warning(
                    "No unused access analyzer found. "
                    "Create one with: aws accessanalyzer create-analyzer "
                    "--analyzer-name unused-access-analyzer "
                    "--type ACCOUNT_UNUSED_ACCESS (or ORGANIZATION_UNUSED_ACCESS) "
                    '--configuration \'{"unusedAccess": {"unusedAccessAge": 1}}\''
                )
                return []
            
            logger.info(f"Using analyzer: {self.analyzer_arn}")
            
            findings = []
            
            # Use list_findings_v2 for ACCOUNT_UNUSED_ACCESS analyzer type
            paginator = self.client.get_paginator("list_findings_v2")
            
            page_iterator = paginator.paginate(
                analyzerArn=self.analyzer_arn,
                filter={
                    "findingType": {
                        "eq": ["UnusedPermission"]
                    },
                    "resourceType": {
                        "eq": ["AWS::IAM::Role"]
                    },
                    "status": {
                        "eq": ["ACTIVE"]
                    }
                }
            )
            
            for page in page_iterator:
                for finding_summary in page.get("findings", []):
                    finding_id = finding_summary["id"]
                    
                    # Get detailed finding info
                    finding_details = self._get_finding_details(finding_id)
                    if not finding_details:
                        continue
                    
                    # Get policy recommendation from Access Analyzer
                    recommendation = self._get_finding_recommendation(finding_id)
                    
                    # Extract account ID from resource ARN (for org-level findings)
                    resource_arn = finding_details.get("resource", "")
                    finding_account_id = self.extract_account_id(resource_arn) or self.account_id

                    findings.append({
                        "id": finding_id,
                        "details": finding_details,
                        "recommendation": recommendation,
                        "account_id": finding_account_id
                    })
            
            logger.info(f"Retrieved {len(findings)} findings with recommendations")
            return findings
            
        except Exception as e:
            logger.warning(f"Error querying Access Analyzer: {str(e)}", exc_info=True)
            raise


    def _get_finding_details(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific finding
        
        Args:
            finding_id: The ID of the finding
            
        Returns:
            Finding details dictionary or None if error
        """
        try:
            response = self.client.get_finding_v2(
                analyzerArn=self.analyzer_arn,
                id=finding_id
            )
            return response
        except Exception as e:
            logger.warning(f"Error getting finding details for {finding_id}: {str(e)}")
            return None

    def _get_finding_recommendation(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """
        Get policy recommendation for a finding using generate-finding-recommendation API.
        
        This is the key integration point - Access Analyzer provides the recommended
        policy with unused permissions removed, so we don't need to generate it ourselves.
        
        Args:
            finding_id: The ID of the finding
            
        Returns:
            Recommendation with recommended policy, or None if unavailable
        """
        try:
            logger.info(f"Generating recommendation for finding: {finding_id}")
            
            # Start recommendation generation (async operation)
            self.client.generate_finding_recommendation(
                analyzerArn=self.analyzer_arn,
                id=finding_id
            )
            
            # Poll for recommendation completion
            max_attempts = 10
            for attempt in range(max_attempts):
                response = self.client.get_finding_recommendation(
                    analyzerArn=self.analyzer_arn,
                    id=finding_id
                )
                
                status = response.get("status")
                
                if status == "SUCCEEDED":
                    logger.info(f"Recommendation ready for finding: {finding_id}")
                    return {
                        "status": "SUCCEEDED",
                        "recommendedPolicy": response.get("recommendedPolicy"),
                        "recommendationType": response.get("recommendationType"),
                        "recommendedSteps": response.get("recommendedSteps", [])
                    }
                elif status == "FAILED":
                    logger.warning(f"Recommendation failed for finding {finding_id}: {response.get('error')}")
                    return {
                        "status": "FAILED",
                        "error": response.get("error")
                    }
                elif status == "IN_PROGRESS":
                    logger.debug(f"Recommendation in progress for {finding_id}, attempt {attempt + 1}")
                    time.sleep(2)  # nosemgrep: arbitrary-sleep - Poll interval for async recommendation generation
                else:
                    logger.warning(f"Unknown recommendation status: {status}")
                    break
            
            logger.warning(f"Recommendation timed out for finding: {finding_id}")
            return {"status": "TIMEOUT"}
            
        except self.client.exceptions.ValidationException as e:
            # Some findings may not support recommendations
            logger.warning(f"Recommendation not available for finding {finding_id}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error getting recommendation for {finding_id}: {str(e)}")
            return None

    def get_finding_with_recommendation(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a single finding with its recommendation.
        Useful for processing individual findings.
        
        Args:
            finding_id: The ID of the finding
            
        Returns:
            Finding with details and recommendation
        """
        details = self._get_finding_details(finding_id)
        if not details:
            return None
            
        recommendation = self._get_finding_recommendation(finding_id)
        
        return {
            "id": finding_id,
            "details": details,
            "recommendation": recommendation
        }

    def get_unused_role_findings(self, max_results: int = 0) -> List[Dict[str, Any]]:
        """
        Get UnusedIAMRole findings from Access Analyzer.

        These are roles that have never been assumed within the analysis period.
        No recommendation is needed — the remediation is to disable or delete.

        Args:
            max_results: Maximum number of findings to return (0 = unlimited)

        Returns:
            List of findings for completely unused roles
        """
        try:
            logger.info("Querying IAM Access Analyzer for unused IAM role findings")

            if not self.analyzer_arn:
                logger.warning("No unused access analyzer found")
                return []

            findings = []
            paginator = self.client.get_paginator("list_findings_v2")

            page_iterator = paginator.paginate(
                analyzerArn=self.analyzer_arn,
                filter={
                    "findingType": {
                        "eq": ["UnusedIAMRole"]
                    },
                    "resourceType": {
                        "eq": ["AWS::IAM::Role"]
                    },
                    "status": {
                        "eq": ["ACTIVE"]
                    }
                }
            )

            for page in page_iterator:
                for finding_summary in page.get("findings", []):
                    if max_results > 0 and len(findings) >= max_results:
                        logger.info(f"Reached max_results limit ({max_results}), stopping fetch")
                        break

                    finding_id = finding_summary["id"]
                    finding_details = self._get_finding_details(finding_id)
                    if not finding_details:
                        continue

                    resource_arn = finding_details.get("resource", "")
                    finding_account_id = self.extract_account_id(resource_arn) or self.account_id

                    findings.append({
                        "id": finding_id,
                        "details": finding_details,
                        "recommendation": None,  # No recommendation needed for unused roles
                        "account_id": finding_account_id
                    })

                if max_results > 0 and len(findings) >= max_results:
                    break

            logger.info(f"Retrieved {len(findings)} unused IAM role findings")
            return findings

        except Exception as e:
            logger.warning(f"Error querying unused role findings: {str(e)}", exc_info=True)
            raise

