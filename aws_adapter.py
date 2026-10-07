import boto3
from botocore.exceptions import ClientError
import streamlit as st

class AWSCloudAdapter:
    def __init__(self, region_name="us-east-1"):
        self.region_name = region_name
        
        # Check if running on Streamlit Cloud with Secrets configured
        if "AWS_ACCESS_KEY_ID" in st.secrets:
            self.session = boto3.Session(
                aws_access_key_id=st.secrets["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=st.secrets["AWS_SECRET_ACCESS_KEY"],
                region_name=self.region_name
            )
        else:
            # Fallback to local AWS profile/credentials
            self.session = boto3.Session(region_name=self.region_name)

    def get_iam_users(self):
        iam = self.session.client('iam')
        users_data = []
        try:
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    
                    # Fetch MFA devices
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    has_mfa = len(mfa_devices) > 0
                    
                    # Fetch attached policies
                    policies = iam.list_attached_user_policies(UserName=username)['AttachedUserPolicies']
                    policy_names = [p['PolicyName'] for p in policies]
                    
                    users_data.append({
                        "username": username,
                        "mfa_enabled": has_mfa,
                        "access_keys_age_days": 10,
                        "attached_policies": policy_names
                    })
        except ClientError as e:
            st.error(f"IAM API Error: {e}")
        return users_data

    def get_storage_buckets(self):
        s3 = self.session.client('s3')
        buckets_data = []
        try:
            response = s3.list_buckets()
            for bucket in response.get('Buckets', []):
                name = bucket['Name']
                
                # Check Public Access Block
                pab_status = False
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    config = pab['PublicAccessBlockConfiguration']
                    pab_status = all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ])
                except ClientError:
                    pab_status = False
                
                # Check Encryption
                enc_status = False
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    enc_status = True
                except ClientError:
                    enc_status = False

                buckets_data.append({
                    "bucket_name": name,
                    "public_access_block": pab_status,
                    "encrypted_at_rest": enc_status
                })
        except ClientError as e:
            st.error(f"S3 API Error: {e}")
        return buckets_data

    def get_standardized_config(self):
        return {
            "iam_users": self.get_iam_users(),
            "storage_buckets": self.get_storage_buckets(),
            "security_groups": []
        }