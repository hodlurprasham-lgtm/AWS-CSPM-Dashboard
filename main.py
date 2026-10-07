from aws_adapter import AWSCloudAdapter
from auditor_engine import CloudSecurityAuditor
from aws_remediator import AWSRemediator

def main():
    print("=" * 70)
    print(" CONNECTING TO LIVE AWS ENVIRONMENT VIA BOTO3...")
    print("=" * 70)
    
    adapter = AWSCloudAdapter(region_name="us-east-1")
    remediator = AWSRemediator(region_name="us-east-1")
    
    # 1. Pre-Remediation Baseline Audit
    live_config = adapter.get_standardized_config()
    auditor = CloudSecurityAuditor(live_config)
    pre_score, pre_issues = auditor.generate_report()
    
    print("\n" + "=" * 70)
    print(f" PRE-REMEDIATION AWS SECURITY POSTURE SCORE: {pre_score:.2f}%")
    print(f" Active Violations Detected: {len(pre_issues)}")
    print("=" * 70)
    
    for issue in pre_issues:
        print(f"[{issue['SEVERITY'] if 'SEVERITY' in issue else issue['severity']}] {issue['category']} -> {issue['resource']}: {issue['issue']}")

    if not pre_issues:
        print("\n🎉 Zero violations detected! Your AWS environment is fully compliant.")
        return

    # 2. Safety Approval Workflow
    print("\n" + "-" * 70)
    print(" AUTOMATED REMEDIATION OPTIONS")
    print("-" * 70)
    print(" 1. Run DRY-RUN Simulation (Preview changes without applying)")
    print(" 2. Execute LIVE AUTO-REMEDIATION (Apply security patches to AWS)")
    print(" 3. Exit without action")
    
    choice = input("\nSelect an option (1/2/3): ").strip()

    if choice == "1":
        print("\n--- EXECUTING DRY-RUN SIMULATION ---")
        for issue in pre_issues:
            if issue['category'] == 'Storage':
                remediator.fix_s3_public_access(issue['resource'], dry_run=True)
                remediator.fix_s3_encryption(issue['resource'], dry_run=True)
        print("-> Dry run complete. Zero changes applied to live infrastructure.")

    elif choice == "2":
        confirm = input("\n⚠️ WARNING: This will mutate live AWS infrastructure configurations. Proceed? (y/n): ").strip().lower()
        if confirm == 'y':
            print("\n--- EXECUTING LIVE AUTO-REMEDIATION ---")
            for issue in pre_issues:
                if issue['category'] == 'Storage':
                    remediator.fix_s3_public_access(issue['resource'], dry_run=False)
                    remediator.fix_s3_encryption(issue['resource'], dry_run=False)

            # 3. Post-Remediation Re-Validation Audit
            print("\nRe-auditing live AWS infrastructure to verify compliance...")
            post_config = adapter.get_standardized_config()
            post_auditor = CloudSecurityAuditor(post_config)
            post_score, post_issues = post_auditor.generate_report()

            print("\n" + "=" * 70)
            print(" AUTOMATED REMEDIATION SUMMARY REPORT")
            print("=" * 70)
            print(f" Pre-Remediation Score  : {pre_score:.2f}% ({len(pre_issues)} Violations)")
            print(f" Post-Remediation Score : {post_score:.2f}% ({len(post_issues)} Violations Remaining)")
            print("=" * 70)
        else:
            print("Remediation canceled by operator.")
    else:
        print("Exiting pipeline.")

if __name__ == "__main__":
    main()