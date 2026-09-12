import json
import requests
import streamlit as st


OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.2:3b"


def classify_risk(event_name):
    high_risk = {
        "CreateAccessKey",
        "AttachUserPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "UpdateAssumeRolePolicy",
        "CreateLoginProfile"
    }

    medium_risk = {
        "CreateUser",
        "CreateRole",
        "CreateServiceLinkedRole",
        "AddUserToGroup",
        "ConsoleLogin",
        "DeleteUser",
        "DeleteRole"
    }

    if event_name in high_risk:
        return "HIGH"

    if event_name in medium_risk:
        return "MEDIUM"

    return "LOW"


def mitre_mapping(event_name):
    mappings = {
        "ConsoleLogin": "Valid Accounts",
        "CreateAccessKey": "Account Manipulation",
        "CreateUser": "Create Account",
        "CreateRole": "Requires analyst review",
        "CreateServiceLinkedRole": "Requires analyst review",
        "AddUserToGroup": "Account Manipulation",
        "AttachUserPolicy": "Account Manipulation",
        "PutUserPolicy": "Account Manipulation",
        "PutRolePolicy": "Account Manipulation",
        "UpdateAssumeRolePolicy": "Account Manipulation",
        "CreateLoginProfile": "Account Manipulation"
    }

    return mappings.get(
        event_name,
        "Requires analyst review"
    )

def extract_event(data):
    identity = data.get("userIdentity", {})

    if identity.get("type") == "Root":
        username = "Root"
    else:
        username = (
            identity.get("userName")
            or identity.get("principalId")
            or "Unknown"
        )

    return {
        "event_name": data.get("eventName", "Unknown"),
        "event_source": data.get("eventSource", "Unknown"),
        "event_time": data.get("eventTime", "Unknown"),
        "region": data.get("awsRegion", "Unknown"),
        "source_ip": data.get("sourceIPAddress", "Unknown"),
        "user_agent": data.get("userAgent", "Unknown"),
        "username": username,
        "identity_type": identity.get("type", "Unknown"),
        "request_parameters": data.get("requestParameters", {})
    }

def analyze_with_ai(event):
    risk = classify_risk(event["event_name"])
    mitre = mitre_mapping(event["event_name"])

    prompt = f"""
You are assisting a cloud security analyst.

Analyze the following AWS CloudTrail event.

Do not invent information that is not provided.
Do not assume the event is malicious just because it is security relevant.

EVENT NAME:
{event['event_name']}

EVENT SOURCE:
{event['event_source']}

EVENT TIME:
{event['event_time']}

AWS REGION:
{event['region']}

SOURCE IP:
{event['source_ip']}

USER:
{event['username']}

IDENTITY TYPE:
{event['identity_type']}

USER AGENT:
{event['user_agent']}

REQUEST PARAMETERS:
{json.dumps(event['request_parameters'], indent=2)}

RISK CLASSIFICATION:
{risk}

MITRE ATT&CK MAPPING:
{mitre}

Return exactly these sections:

INCIDENT SUMMARY
Explain what occurred.

SECURITY SIGNIFICANCE
Explain why this AWS API activity may matter to a security analyst.

INVESTIGATION STEPS
Give 3-5 specific investigation steps.

RECOMMENDED RESPONSE
Give practical security recommendations.

MITRE ATT&CK
Explain the supplied mapping.
If there is not enough evidence to confirm malicious behavior,
clearly state that.
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

    return response.json()["message"]["content"]


st.set_page_config(
    page_title="AI AWS Security Analyzer",
    page_icon="🔐",
    layout="wide"
)

st.title("AI AWS Security Analyzer")

st.write(
    "Analyze AWS CloudTrail events using Python, "
    "MITRE ATT&CK, and a locally hosted AI model."
)

uploaded_file = st.file_uploader(
    "Upload an AWS CloudTrail JSON event",
    type=["json"]
)

if uploaded_file is not None:

    try:
        data = json.load(uploaded_file)

        event = extract_event(data)

        risk = classify_risk(event["event_name"])
        mitre = mitre_mapping(event["event_name"])

        st.subheader("AWS CloudTrail Event")

        col1, col2, col3 = st.columns(3)

        col1.metric("Risk", risk)
        col2.metric("AWS Region", event["region"])
        col3.metric("Identity", event["identity_type"])

        st.subheader("Event Name")
        st.code(event["event_name"])

        st.subheader("AWS Service")
        st.write(event["event_source"])

        st.subheader("User")
        st.write(event["username"])

        st.subheader("Source IP")
        st.write(event["source_ip"])

        st.subheader("MITRE ATT&CK")
        st.write(mitre)

        if st.button("Analyze with AI"):

            with st.spinner("Analyzing CloudTrail event..."):

                try:
                    result = analyze_with_ai(event)

                    st.subheader("AI Security Analysis")
                    st.markdown(result)

                except requests.RequestException as error:

                    st.error(
                        "Could not connect to Ollama. "
                        "Make sure Ollama is running."
                    )

                    st.code(str(error))

        with st.expander("View Raw CloudTrail JSON"):
            st.json(data)

    except json.JSONDecodeError:

        st.error("Uploaded file is not valid JSON.")

    except Exception as error:

        st.error("CloudTrail event could not be processed.")
        st.code(str(error))
