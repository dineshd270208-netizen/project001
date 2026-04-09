import logging
from logger import AuditLogger

logger = logging.getLogger(__name__)

class Remediator:
    def __init__(self, s3_client=None, ec2_client=None):
        self.s3_client = s3_client
        self.ec2_client = ec2_client
        self.audit = AuditLogger()

    def block_public_access(self, bucket_name):
        """Automated Remediation: Apply Public Access Block on S3 Bucket"""
        logger.info(f"Remediating S3 Bucket: {bucket_name}")
        try:
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            logger.info(f"SUCCESS: Blocked public access for bucket {bucket_name}")
            self.audit.log_remediation("S3_PUBLIC_ACCESS", f"Applied PublicAccessBlock to {bucket_name}")
        except Exception as e:
            logger.error(f"Failed to remediate bucket {bucket_name}: {e}")

    def revoke_unrestricted_ssh(self, sg_id, rule):
        """Automated Remediation: Revoke unrestricted SSH rule from Security Group"""
        logger.info(f"Remediating Security Group: {sg_id}")
        try:
            # We explicitly revoke just the specific bad permission
            # In a real environment we might want to replace it with a corporate VPN IP instead
            self.ec2_client.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[rule]
            )
            logger.info(f"SUCCESS: Revoked unrestricted SSH ingress from {sg_id}")
            self.audit.log_remediation("SG_UNRESTRICTED_SSH", f"Revoked 0.0.0.0/0 on port 22 from {sg_id}")
        except Exception as e:
            logger.error(f"Failed to remediate Security Group {sg_id}: {e}")
