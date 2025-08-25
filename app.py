# To run this code, you will need to install the following libraries:
# pip install Flask requests python-dotenv pyjwt cryptography

import os
import secrets
import hashlib
import base64
import json
import uuid
import jwt
from flask import Flask, request, redirect, jsonify, session
import requests
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Load environment variables from the .env file
load_dotenv()

# --- Configuration: Replace these with your actual app details ---
CLIENT_ID = os.getenv("CLIENT_ID", "YOUR_CLIENT_ID")
# The private key is now loaded securely from the .env file
PRIVATE_KEY_PEM = os.getenv("PRIVATE_KEY_PEM")
JWKS_KID = os.getenv("JWKS_KID")
LAUNCH_URL = "https://aakashk-upx.github.io/ecw-jwks/launch"
REDIRECT_URL = "https://aakashk-upx.github.io/ecw-jwks/redirect"

# The scopes requested by your application, as configured in the eCW Developer Portal.
REQUESTED_SCOPES = (
    "launch openid fhirUser "
    "user/Patient.read user/DocumentReference.read user/Procedure.read user/Medication.read "
    "user/AllergyIntolerance.read user/Encounter.read user/Observation.read "
    "user/ServiceRequest.read user/DiagnosticReport.read user/Organization.read "
    "user/PractitionerRole.read user/Immunization.read user/MedicationRequest.read "
    "user/MedicationAdministration.read user/Goal.read user/Practitioner.read "
    "user/CareTeam.read user/Condition.read user/Provenance.read user/CarePlan.read"
)

app = Flask(__name__)
# A secret key is required for Flask sessions to securely store temporary data.
app.secret_key = secrets.token_hex(16) 

# --- Routes for the SMART on FHIR Launch Sequence ---

@app.route("/ecw-jwks/launch", methods=["GET"])
def launch():
    """
    Handles the initial EHR launch request from eClinicalWorks.
    This is the first step of the SMART on FHIR launch sequence.
    """
    iss = request.args.get("iss")
    launch_context = request.args.get("launch")

    if not iss or not launch_context:
        return jsonify({"error": "Missing 'iss' or 'launch' parameter"}), 400

    auth_server_url = "https://staging-auth.ecwcloud.com/oauth2/authorize" 
    token_server_url = "https://staging-auth.ecwcloud.com/oauth2/token"

    session["iss"] = iss
    session["launch_context"] = launch_context
    session["token_server_url"] = token_server_url

    state = secrets.token_urlsafe(16)
    session["state"] = state

    code_verifier = secrets.token_urlsafe(64)
    session["code_verifier"] = code_verifier
    
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8").replace("=", "")
    
    auth_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URL,
        "scope": REQUESTED_SCOPES,
        "aud": iss,
        "launch": launch_context,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"{auth_server_url}?{requests.compat.urlencode(auth_params)}"
    return redirect(auth_url)

@app.route("/ecw-jwks/redirect", methods=["GET"])
def redirect_handler():
    """
    Handles the redirect from the authorization server after the user has approved the app.
    This is the second step of the SMART on FHIR launch sequence.
    """
    if request.args.get("state") != session.get("state"):
        return jsonify({"error": "Invalid state parameter"}), 400

    auth_code = request.args.get("code")
    token_server_url = session.get("token_server_url")
    fhir_base_url = session.get("iss")

    if not auth_code or not token_server_url or not fhir_base_url:
        return jsonify({"error": "Missing required parameters from session"}), 400
        
    # Generate the JWT for client authentication
    # This is a key part of the JWT-based authentication flow.
    # The 'aud' (audience) for the JWT is the token server URL itself.
    
    # Load the private key from the .env file
    private_key_bytes = PRIVATE_KEY_PEM.encode("utf-8")
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )

    # JWT header with key ID
    jwt_header = {
        "alg": "RS384",
        "kid": JWKS_KID,
    }
    
    # JWT claims
    jwt_claims = {
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": token_server_url,
        "exp": jwt.utils.datetime.utcnow() + jwt.utils.timedelta(minutes=5),
        "jti": str(uuid.uuid4()), # JSON Token ID
    }
    
    # Generate the JWT
    client_assertion = jwt.encode(
        jwt_claims,
        private_key,
        algorithm="RS384",
        headers=jwt_header
    )

    # 2. Exchange the authorization code for an access token
    # This is a backend POST request
    token_payload = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URL,
        "code_verifier": session.get("code_verifier"),
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion
    }

    try:
        # Perform the token exchange
        token_response = requests.post(token_server_url, data=token_payload)
        token_response.raise_for_status()
        token_data = token_response.json()

        # Extract the access token and other context from the response
        access_token = token_data.get("access_token")
        patient_id = token_data.get("patient")
        
        # Now you can use the access token to make FHIR API calls
        fhir_headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/fhir+json"
        }
        patient_url = f"{fhir_base_url}/Patient/{patient_id}"
        
        patient_response = requests.get(patient_url, headers=fhir_headers)
        patient_data = patient_response.json()
        
        # Display the patient data
        return jsonify({
            "status": "success",
            "message": "Successfully authenticated and fetched patient data.",
            "patient_data": patient_data
        })

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Token exchange failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(port=8080, debug=True)
