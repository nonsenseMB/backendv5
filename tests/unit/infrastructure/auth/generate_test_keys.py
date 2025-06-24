"""Generate test RSA keys for unit tests"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from jose import jwk
import json

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

# Export as PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Private Key (PEM):")
print(private_pem.decode())
print("\nPublic Key (PEM):")
print(public_pem.decode())

# Create JWK from private key
jwk_key = jwk.construct(private_pem, algorithm='RS256')
jwk_dict = json.loads(jwk_key.to_json())
jwk_dict["kid"] = "test-key-1"
jwk_dict["use"] = "sig"

print("\nJWK (for signing):")
print(json.dumps(jwk_dict, indent=2))

# Create public JWK
public_jwk = {k: v for k, v in jwk_dict.items() if k not in ["d", "p", "q", "dp", "dq", "qi"]}
print("\nPublic JWK (for JWKS):")
print(json.dumps(public_jwk, indent=2))