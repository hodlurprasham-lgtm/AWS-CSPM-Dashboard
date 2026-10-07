import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

class AWSCloudAdapter:
    def __init__(self, region_name="us-east-1"):
        self.iam = boto3.client("iam", region_name=region_name)
        self.s3 = boto3.client("s3", region_name=region_name)
        self.ec2 = boto3.client("ec2", region_name=region_name)

    def fetch_iam_users(self):
        iam_data = []
        try:
            users = self.iam.list_users().get("Users", [])
            for user in users:
                username = user["UserName"]
                
                mfa_devices = self.iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                mfa_enabled = len(mfa_devices) > 0

                keys = self.iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                max_age_days = 0
                for key in keys:
                    age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                    if age > max_age_days:
                        max_age_days = age

                policies = self.iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                attached = [p["PolicyName"] for p in policies]

                iam_data.append({
                    "username": username,
                    "mfa_enabled": mfa_enabled,
                    "access_keys_age_days": max_age_days,
                    "attached_policies": attached
                })
        except ClientError as e:
            print(f"AWS IAM Error: {e}")
        return iam_data

    def fetch_s3_buckets(self):
        bucket_data = []
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
            for b in buckets:
                name = b["Name"]
                public_blocked = False
                try:
                    pab = self.s3.get_public_access_block(Bucket=name)
                    cfg = pab.get("PublicAccessBlockConfiguration", {})
                    public_blocked = all([
                        cfg.get("BlockPublicAcls", False),
                        cfg.get("IgnorePublicAcls", False),
                        cfg.get("BlockPublicPolicy", False),
                        cfg.get("RestrictPublicBuckets", False)
                    ])
                except ClientError:
                    public_blocked = False

                encrypted = False
                try:
                    enc = self.s3.get_bucket_encryption(Bucket=name)
                    if enc.get("ServerSideEncryptionConfiguration"):
                        encrypted = True
                except ClientError:
                    encrypted = False

                bucket_data.append({
                    "bucket_name": name,
                    "public_access_block": public_blocked,
                    "encrypted_at_rest": encrypted,
                    "versioning": True
                })
        except ClientError as e:
            print(f"AWS S3 Error: {e}")
        return bucket_data

    def fetch_security_groups(self):
        sg_data = []
        try:
            groups = self.ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in groups:
                group_id = sg["GroupId"]
                desc = sg.get("Description", "No Description")
                inbound_rules = []

                for perm in sg.get("IpPermissions", []):
                    port = perm.get("FromPort", 0)
                    protocol = perm.get("IpProtocol", "ALL").upper()
                    for ip in perm.get("IpRanges", []):
                        inbound_rules.append({
                            "port": port,
                            "cidr": ip.get("CidrIp", ""),
                            "protocol": protocol
                        })

                sg_data.append({
                    "group_id": group_id,
                    "description": desc,
                    "inbound_rules": inbound_rules
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedOperation':
                print("[!] EC2 Security Group inspection restricted by account policy (SCP). Skipping vector.")
            else:
                print(f"AWS Security Group Error: {e}")
        return sg_data

    def get_standardized_config(self):
        return {
            "iam_users": self.fetch_iam_users(),
            "storage_buckets": self.fetch_s3_buckets(),
            "security_groups": self.fetch_security_groups()
        }