import json
import requests
import streamlit as st


OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.2:3b"


def severity_label(score):
    try:
        score = float(score)

        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    except (TypeError, ValueError):
        return "UNKNOWN"


def map_mitre_tactic(finding_type):
    mappings = {
        "CredentialAccess": "Credential Access",
        "PrivilegeEscalation": "Privilege Escalation",
        "InitialAccess": "Initial Access",
        "Persistence": "Persistence",
        "DefenseEvasion": "Defense Evasion",
        "Discovery": "Discovery",
        "Exfiltration": "Exfiltration",
        "Impact": "Impact",
        "Recon": "Reconnaissance",
        "Execution": "Execution",
    }

    category = finding_type.split(":")[0]

    return mappings.get(category, "Requires analyst review")


def extract_finding(data):

    # Supports standard GuardDuty JSON and EventBridge-wrapped GuardDuty data
    finding = data.get("detail", data)

    finding_type = finding.get("type", "Unknown")
    severity_score = finding.get("severity", 0)

    resource = finding.get("resource", {})
    service = finding.get("service", {})

    return {
        "title": finding.get("title", finding_type),
        "type": finding_type,
        "description": finding.get(
            "description",
            "No description provided."
        ),
        "severity_score": severity_score,
        "severity": severity_label(severity_score),
        "region": finding.get("region", "Unknown"),
        "resource_type": resource.get(
            "resourceType",
            "Unknown"
        ),
        "mitre_tactic": map_mitre_tactic(finding_type),
        "resource": resource,
        "action": service.get("action", {}),
    }


def analyze_with_ai(finding):

    prompt = f"""
You are assisting a cybersecurity analyst investigating an
Amazon AWS GuardDuty finding.

Analyze ONLY the evidence below.

Do not invent IP addresses, usernames, resources, actions,
or other facts that are not supplied.

FINDING TITLE:
{finding['title']}

FINDING TYPE:
{finding['type']}

AWS SEVERITY:
{finding['severity']}

AWS SEVERITY SCORE:
{finding['severity_score']}

AWS REGION:
{finding['region']}

RESOURCE TYPE:
{finding['resource_type']}

DESCRIPTION:
{finding['description']}

MITRE ATT&CK TACTIC:
{finding['mitre_tactic']}

RESOURCE DATA:
{json.dumps(finding['resource'], indent=2)}

ACTION DATA:
{json.dumps(finding['action'], indent=2)}

Return these sections:

INCIDENT SUMMARY
Give a concise technical explanation of what happened.

WHY IT MATTERS
Explain the possible security impact.

INVESTIGATION STEPS
Provide 3-5 specific investigation steps for an AWS security analyst.

RECOMMENDED RESPONSE
Provide practical containment or remediation recommendations.

MITRE ATT&CK
State the supplied MITRE ATT&CK tactic.
Only suggest a technique if the evidence clearly supports one.
Otherwise state that technique validation is required.
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "stream": False
        },
        timeout=120
    )

    response.raise_for_status()

    result = response.json()

    return result["message"]["content"]


# -------------------------
# STREAMLIT USER INTERFACE
# -------------------------

st.set_page_config(
    page_title="AI AWS Security Analyzer",
    page_icon="🔐",
    layout="wide"
)

st.title("AI AWS Security Analyzer")

st.write(
    "Analyze Amazon GuardDuty security findings using "
    "Python and a locally hosted generative AI model."
)

uploaded_file = st.file_uploader(
    "Upload an Amazon GuardDuty JSON finding",
    type=["json"]
)

if uploaded_file is not None:

    try:
        data = json.load(uploaded_file)

        finding = extract_finding(data)

        st.subheader("AWS Security Finding")

        column1, column2, column3 = st.columns(3)

        column1.metric(
            "Severity",
            finding["severity"]
        )

        column2.metric(
            "AWS Severity Score",
            finding["severity_score"]
        )

        column3.metric(
            "Resource",
            finding["resource_type"]
        )

        st.subheader("Finding Type")
        st.code(finding["type"])

        st.subheader("Description")
        st.write(finding["description"])

        st.subheader("MITRE ATT&CK Tactic")
        st.write(finding["mitre_tactic"])

        st.subheader("AWS Region")
        st.write(finding["region"])

        if st.button("Analyze with AI"):

            with st.spinner("Analyzing AWS finding..."):

                try:
                    analysis = analyze_with_ai(finding)

                    st.subheader("AI Security Analysis")

                    st.markdown(analysis)

                except requests.RequestException as error:

                    st.error(
                        "Could not connect to Ollama. "
                        "Make sure Ollama is running."
                    )

                    st.code(str(error))

        with st.expander("View Raw AWS JSON"):

            st.json(data)

    except json.JSONDecodeError:

        st.error("The uploaded file is not valid JSON.")

    except Exception as error:

        st.error("The GuardDuty finding could not be processed.")

        st.code(str(error))