from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

#Gerando par de chaves ECDSA e as salvando em um arquivo .pem

# Gerar chave privada
private_key = ec.generate_private_key(ec.SECP256R1())

# chave privada em PEM
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# chave pública e salvar em PEM
public_key = private_key.public_key()
with open("public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
