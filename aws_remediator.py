import boto3
from botocore.exceptions import ClientError

class AWSRemediator:
    def __init__(self, region_name="us-east-1"):
        self.s3 = boto3.client("s3", region_name=region_name)

    def fix_s3_public_access(self, bucket_name, dry_run=False):
        """Enforces Block Public Access settings on an S3 bucket."""
        if dry_run:
            print(f"[DRY RUN] Would enforce Public Access Block on bucket: {bucket_name}")
            return True

        try:
            self.s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            print(f"[REMEDIATED] Successfully enabled Public Access Block on: {bucket_name}")
            return True
        except ClientError as e:
            print(f"[ERROR] Failed to remediate S3 bucket {bucket_name}: {e}")
            return False

    def fix_s3_encryption(self, bucket_name, dry_run=False):
        """Enforces Default Server-Side SSE-S3 Encryption on an S3 bucket."""
        if dry_run:
            print(f"[DRY RUN] Would enable SSE-S3 Encryption on bucket: {bucket_name}")
            return True

        try:
            self.s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )
            print(f"[REMEDIATED] Successfully enabled SSE-S3 Encryption on: {bucket_name}")
            return True
        except ClientError as e:
            print(f"[ERROR] Failed to enable encryption on {bucket_name}: {e}")
            return False