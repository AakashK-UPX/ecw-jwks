# To run this code, you will need to install the following libraries:
# pip install Flask requests pyjwt cryptography

import os
import secrets
import hashlib
import base64
import json
import uuid
import jwt
from flask import Flask, request, redirect, jsonify, session
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Configuration: Hardcoded app details ---
# IMPORTANT: Hardcoding secrets is NOT a secure practice for production environments.
# This is for testing purposes only.
CLIENT_ID = "uf2cZkTF-ApHsH89m62qHgO5IyaMR9rVVMaA077M4wk"
JWKS_KID = "650c8b7e-6a2a-44fa-84dd-27221a582b15"
LAUNCH_URL = "https://aakashk-upx.github.io/ecw-jwks/launch/"
REDIRECT_URL = "https://aakashk-upx.github.io/ecw-jwks/redirect/"

# The scopes requested by your application, as configured in the eCW Developer Portal.
# CORRECTED: This list has been filtered to include only those supported by eCW sandbox.
# REQUESTED_SCOPES = (
#     "launch openid fhirUser "
#     "user/Patient.read user/DocumentReference.read user/Procedure.read "
#     "user/Medication.read user/AllergyIntolerance.read user/Encounter.read "
#     "user/Observation.read user/DiagnosticReport.read user/Organization.read "
#     "user/PractitionerRole.read user/Immunization.read user/MedicationRequest.read "
#     "user/MedicationAdministration.read user/Goal.read user/Practitioner.read "
#     "user/CareTeam.read user/Condition.read user/Provenance.read user/CarePlan.read"
# )
REQUESTED_SCOPES = (
    "fhirUser patient/Patient.read"
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16) 

# --- Routes for the SMART on FHIR Launch Sequence ---

@app.route("/ecw-jwks/launch", methods=["GET"])
def launch():
    iss = request.args.get("iss")
    launch_context = request.args.get("launch")

    if not iss or not launch_context:
        return jsonify({"error": "Missing 'iss' or 'launch' parameter"}), 400

    # CORRECTED: Use the correct authorization and token URLs from the discovery document
    auth_server_url = "https://staging-oauthserver.ecwcloud.com/oauth/oauth2/authorize" 
    token_server_url = "https://staging-oauthserver.ecwcloud.com/oauth/oauth2/token"

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
        "launch": launch_context,
        "state": state,
        "scope": REQUESTED_SCOPES,
        "aud": iss,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"{auth_server_url}?{requests.compat.urlencode(auth_params)}"
    return redirect(auth_url)

@app.route("/ecw-jwks/redirect", methods=["GET"])
def redirect_handler():
    if request.args.get("state") != session.get("state"):
        return jsonify({"error": "Invalid state parameter"}), 400

    auth_code = request.args.get("code")
    token_server_url = session.get("token_server_url")
    fhir_base_url = session.get("iss")

    if not auth_code or not token_server_url or not fhir_base_url:
        return jsonify({"error": "Missing required parameters from session"}), 400
        
    # Read the private key directly from the file
    try:
        with open("private_key.pem", "rb") as key_file:
            private_key_bytes = key_file.read()
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None,
                backend=default_backend()
            )
    except FileNotFoundError:
        return jsonify({"error": "Private key file not found. Please ensure private_key.pem is in the same directory as app.py"}), 500
    except Exception as e:
        return jsonify({"error": f"Failed to load private key: {str(e)}"}), 500

    jwt_header = {
        "alg": "RS384",
        "kid": JWKS_KID,
    }
    
    jwt_claims = {
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": token_server_url,
        "exp": jwt.utils.datetime.utcnow() + jwt.utils.timedelta(minutes=5),
        "jti": str(uuid.uuid4()),
    }
    
    client_assertion = jwt.encode(
        jwt_claims,
        private_key,
        algorithm="RS384",
        headers=jwt_header
    )

    token_payload = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URL,
        "code_verifier": session.get("code_verifier"),
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion
    }

    try:
        token_response = requests.post(token_server_url, data=token_payload)
        token_response.raise_for_status()
        token_data = token_response.json()

        access_token = token_data.get("access_token")
        patient_id = token_data.get("patient")
        
        fhir_headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/fhir+json"
        }
        patient_url = f"{fhir_base_url}/Patient/{patient_id}"
        
        patient_response = requests.get(patient_url, headers=fhir_headers)
        patient_data = patient_response.json()
        
        return jsonify({
            "status": "success",
            "message": "Successfully authenticated and fetched patient data.",
            "patient_data": patient_data
        })

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Token exchange failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(port=8080, debug=True)
