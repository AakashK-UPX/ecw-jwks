# To run this script, you will need the 'cryptography' library.
# Install it by running:
# pip install cryptography

import json
import base64
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_jwks():
    """
    Generates a new RSA key pair and a JWKS file from the public key.
    
    This function creates a private key and its corresponding public key.
    The public key is then formatted into a JSON Web Key Set (JWKS)
    as required by the SMART on FHIR specification for public key authentication.
    """
    try:
        # Generate a new RSA private key
        print("Generating a new RSA private key...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Serialize the private key to PEM format (for your app's use)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Save the private key to a file. Keep this file very secure and do not
        # commit it to your GitHub repository!
        with open("private_key.pem", "wb") as f:
            f.write(private_pem)
        print("Private key saved to 'private_key.pem'. Keep this file SAFE!")

        # Extract the public key from the private key
        public_key = private_key.public_key()

        # Serialize the public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        print("Public key extracted and ready for JWKS creation.")

        # Get the public key components to build the JWK
        numbers = public_key.public_numbers()
        e_b64 = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
        n_b64 = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")

        # Generate a Key ID (kid) - this should be a unique identifier
        kid = str(uuid.uuid4())

        # Create the JWK object for the public key
        jwk = {
            "kty": "RSA",
            "use": "sig",
            "kid": kid,
            "e": e_b64,
            "n": n_b64
        }
        
        # Create the JWKS object, which is a set of JWKs
        jwks = {
            "keys": [jwk]
        }
        
        # Save the JWKS object to a JSON file
        with open("jwks.json", "w") as f:
            json.dump(jwks, f, indent=4)
        print("JWKS file created successfully as 'jwks.json'.")
        print(f"Your public key has the following kid: {kid}")
        print("You can now commit and push the 'jwks.json' file to your repository.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    generate_jwks()

