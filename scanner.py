import boto3
import json
import logging
from remediator import Remediator
from logger import AuditLogger

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CSPMScanner:
    def __init__(self, role_arn=None):
        self.role_arn = role_arn
        # In a real multi-account setup, we would assume roles into tenant accounts.
        # For simplicity, using default session or assumed role session.
        if self.role_arn:
            sts = boto3.client('sts')
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName='CSPMScanner')['Credentials']
            self.s3_client = boto3.client('s3', aws_access_key_id=creds['AccessKeyId'],
                                          aws_secret_access_key=creds['SecretAccessKey'],
                                          aws_session_token=creds['SessionToken'])
            self.ec2_client = boto3.client('ec2', aws_access_key_id=creds['AccessKeyId'],
                                           aws_secret_access_key=creds['SecretAccessKey'],
                                           aws_session_token=creds['SessionToken'])
        else:
            self.s3_client = boto3.client('s3', region_name='us-east-1')
            self.ec2_client = boto3.client('ec2', region_name='us-east-1')
        
        self.remediator = Remediator(self.s3_client, self.ec2_client)
        self.audit = AuditLogger()

    def scan_s3_buckets(self):
        """Check for S3 buckets with Public Access enabled (CIS Benchmark S3.1)"""
        logger.info("Scanning S3 Buckets for Public Access...")
        try:
            response = self.s3_client.list_buckets()
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                is_public = False
                try:
                    pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    config = pab.get('PublicAccessBlockConfiguration', {})
                    if not (config.get('BlockPublicAcls') and config.get('IgnorePublicAcls') and 
                            config.get('BlockPublicPolicy') and config.get('RestrictPublicBuckets')):
                        is_public = True
                except self.s3_client.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        is_public = True
                    else:
                        logger.error(f"Error checking bucket {bucket_name}: {e}")
                
                if is_public:
                    logger.warning(f"VIOLATION: S3 Bucket {bucket_name} might be public.")
                    self.audit.log_finding("S3_PUBLIC_ACCESS", f"Bucket {bucket_name} has unrestricted public access settings.")
                    # Trigger automated remediation
                    self.remediator.block_public_access(bucket_name)

        except Exception as e:
            logger.error(f"Error listing S3 buckets: {e}")

    def scan_security_groups(self):
        """Check for Security Groups allowing 0.0.0.0/0 on SSH ports (CIS Benchmark EC2.1)"""
        logger.info("Scanning Security Groups for unrestricted access...")
        try:
            response = self.ec2_client.describe_security_groups()
            for sg in response.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    
                    if from_port and to_port and from_port <= 22 <= to_port:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                logger.warning(f"VIOLATION: Security Group {sg_id} ({sg_name}) allows SSH from 0.0.0.0/0.")
                                self.audit.log_finding("SG_UNRESTRICTED_SSH", f"Security group {sg_id} allows SSH from ANYWHERE.")
                                # Trigger automated remediation
                                self.remediator.revoke_unrestricted_ssh(sg_id, rule)
        except Exception as e:
            logger.error(f"Error evaluating Security Groups: {e}")

    def run(self):
        """Continuously scan the environment"""
        logger.info("Starting CSPM Scan...")
        self.scan_s3_buckets()
        self.scan_security_groups()
        logger.info("CSPM Scan completed.")

if __name__ == '__main__':
    # Initialize and run the scanner
    # In a production environment, this would run on a schedule via EventBridge triggering a Lambda function.
    # We loop it or invoke on demand.
    scanner = CSPMScanner()
    scanner.run()
