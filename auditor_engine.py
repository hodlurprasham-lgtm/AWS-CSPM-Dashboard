class CloudSecurityAuditor:
    def __init__(self, cloud_config):
        self.config = cloud_config
        self.findings = []
        self.total_checks = 0
        self.passed_checks = 0

    def audit_iam(self):
        for user in self.config.get("iam_users", []):
            username = user.get("username", "")
            
            # Check MFA
            self.total_checks += 1
            if not user.get("mfa_enabled", False):
                self.findings.append({
                    "severity": "CRITICAL",
                    "category": "IAM",
                    "resource": username,
                    "issue": "MFA is disabled for user account."
                })
            else:
                self.passed_checks += 1

            # Check Key Age (> 90 days)
            self.total_checks += 1
            if user.get("access_keys_age_days", 0) > 90:
                self.findings.append({
                    "severity": "MEDIUM",
                    "category": "IAM",
                    "resource": username,
                    "issue": f"Access key age ({user.get('access_keys_age_days')} days) exceeds 90-day threshold."
                })
            else:
                self.passed_checks += 1

            # Check Wildcard / Admin Policies
            self.total_checks += 1
            if "AdministratorAccess" in user.get("attached_policies", []):
                self.findings.append({
                    "severity": "HIGH",
                    "category": "IAM",
                    "resource": username,
                    "issue": "Overly permissive wildcard policy attached violating Least Privilege."
                })
            else:
                self.passed_checks += 1

    def audit_storage(self):
        for bucket in self.config.get("storage_buckets", []):
            # Check Public Access Block
            self.total_checks += 1
            if not bucket.get("public_access_block", False):
                self.findings.append({
                    "severity": "CRITICAL",
                    "category": "Storage",
                    "resource": bucket.get("bucket_name"),
                    "issue": "S3 Public Access Block is disabled; risk of data leak."
                })
            else:
                self.passed_checks += 1

            # Check Encryption
            self.total_checks += 1
            if not bucket.get("encrypted_at_rest", False):
                self.findings.append({
                    "severity": "HIGH",
                    "category": "Storage",
                    "resource": bucket.get("bucket_name"),
                    "issue": "Server-Side Encryption (SSE-KMS/S3) is disabled."
                })
            else:
                self.passed_checks += 1

    def audit_network_security_groups(self):
        for sg in self.config.get("security_groups", []):
            for rule in sg.get("inbound_rules", []):
                self.total_checks += 1
                port = rule.get("port")
                cidr = rule.get("cidr")
                if port in [22, 3389] and cidr == "0.0.0.0/0":
                    self.findings.append({
                        "severity": "CRITICAL",
                        "category": "Network",
                        "resource": f"{sg.get('group_id')} ({sg.get('description')})",
                        "issue": f"Inbound port {port} open to 0.0.0.0/0 (Global Internet)."
                    })
                else:
                    self.passed_checks += 1

    def generate_report(self):
        self.audit_iam()
        self.audit_storage()
        self.audit_network_security_groups()
        
        if self.total_checks == 0:
            score = 100.00
        else:
            score = (self.passed_checks / self.total_checks) * 100
            
        return score, self.findings