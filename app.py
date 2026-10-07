import streamlit as st
from aws_adapter import AWSCloudAdapter
from auditor_engine import CloudSecurityAuditor
from aws_remediator import AWSRemediator

st.set_page_config(page_title="AWS CSPM & Auto-Remediation Dashboard", layout="wide")

st.title("🛡️ Cloud Security Posture Management (CSPM)")
st.subheader("Automated Cloud Security Auditor & Auto-Remediation Engine")

st.sidebar.header("Controls")
region = st.sidebar.selectbox("AWS Region", ["us-east-1", "us-west-2", "eu-west-1"])

adapter = AWSCloudAdapter(region_name=region)
remediator = AWSRemediator(region_name=region)

run_audit = st.sidebar.button("🔍 Run Live Audit")

# Always do a live audit if score isn't set OR audit button clicked
if "score" not in st.session_state or run_audit:
    with st.spinner("Fetching live infrastructure metadata from AWS..."):
        config = adapter.get_standardized_config()
        auditor = CloudSecurityAuditor(config)
        score, issues = auditor.generate_report()

        st.session_state["score"] = score
        st.session_state["issues"] = issues

# Display Security Score Header
st.metric("Overall Security Posture Score", f"{st.session_state['score']:.2f}%")

st.write("### Active Violations")
if st.session_state["issues"]:
    st.table(st.session_state["issues"])
    
    st.write("---")
    st.write("### Auto-Remediation Controls")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🧪 Run Dry-Run Simulation"):
            st.info("Simulating remediation actions without modifying AWS resources...")
            for issue in st.session_state["issues"]:
                if issue["category"] == "Storage":
                    st.write(f"🧪 **[DRY-RUN]** Would enforce Public Access Block on: `{issue['resource']}`")
                    st.write(f"🧪 **[DRY-RUN]** Would enforce SSE-S3 Encryption on: `{issue['resource']}`")
                elif issue["category"] == "IAM":
                    st.write(f"⚠️ **[DRY-RUN]** IAM MFA required on user `{issue['resource']}` (Requires user hardware token setup).")
            st.success("Dry-run simulation complete. Zero changes applied to live infrastructure.")
    
    with col2:
        if st.button("⚡ Execute Live Auto-Remediation"):
            with st.spinner("Applying live security patches to AWS..."):
                for issue in st.session_state["issues"]:
                    if issue["category"] == "Storage":
                        remediator.fix_s3_public_access(issue["resource"], dry_run=False)
                        remediator.fix_s3_encryption(issue["resource"], dry_run=False)
                
                # Directly execute fresh audit & update state variables in place
                fresh_config = adapter.get_standardized_config()
                fresh_auditor = CloudSecurityAuditor(fresh_config)
                new_score, new_issues = fresh_auditor.generate_report()
                
                st.session_state["score"] = new_score
                st.session_state["issues"] = new_issues
                st.rerun()
else:
    st.success("🎉 Zero active vulnerabilities found! AWS environment is fully compliant.")