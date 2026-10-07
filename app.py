import streamlit as st
from aws_adapter import AWSCloudAdapter
from auditor_engine import CloudSecurityAuditor
from aws_remediator import AWSRemediator

st.set_page_config(page_title="AWS CSPM & Auto-Remediation Dashboard", layout="wide")

st.title("🛡️ Cloud Security Posture Management (CSPM)")
st.subheader("Automated Cloud Security Auditor & Auto-Remediation Engine")

st.sidebar.header("Controls")
region = st.sidebar.selectbox("AWS Region", ["us-east-1", "us-west-2", "eu-west-1"])

# Optional reset button to clear state back to initial screen during demo
if st.sidebar.button("🔄 Reset Dashboard State"):
    st.session_state.clear()
    st.rerun()

adapter = AWSCloudAdapter(region_name=region)
remediator = AWSRemediator(region_name=region)

run_audit = st.sidebar.button("🔍 Run Live Audit")

# Placeholders for dynamic metric and table updates
score_container = st.empty()
violations_container = st.empty()

# ONLY execute audit when 'Run Live Audit' button is clicked
if run_audit:
    with st.spinner("Fetching live infrastructure metadata from AWS..."):
        config = adapter.get_standardized_config()
        auditor = CloudSecurityAuditor(config)
        score, issues = auditor.generate_report()

        st.session_state["score"] = score
        st.session_state["issues"] = issues

# Render controls and score ONLY if 'score' exists in session state
if "score" in st.session_state:
    score_container.metric("Overall Security Posture Score", f"{st.session_state['score']:.2f}%")
    
    st.write("### Active Violations")
    violations_container.table(st.session_state["issues"])

    if st.session_state["issues"]:
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
                    
                    # Immediately query AWS for updated posture
                    fresh_config = adapter.get_standardized_config()
                    fresh_auditor = CloudSecurityAuditor(fresh_config)
                    new_score, new_issues = fresh_auditor.generate_report()
                    
                    # Update session state and refresh dynamic containers on screen
                    st.session_state["score"] = new_score
                    st.session_state["issues"] = new_issues
                    
                    score_container.metric("Overall Security Posture Score", f"{new_score:.2f}%")
                    violations_container.table(new_issues)
                    
                    st.success("S3 Public Access Block & Encryption applied successfully!")
    else:
        st.success("🎉 Zero active vulnerabilities found! AWS environment is fully compliant.")
else:
    st.info("👋 Welcome! Click **🔍 Run Live Audit** in the sidebar to scan your AWS environment.")