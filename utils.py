from cryptography.hazmat.primitives.asymmetric import dh # DH (Diffie-Hellman) para troca de chaves
from cryptography.hazmat.backends import default_backend # Backend padrão para operações criptográficas
from cryptography.hazmat.primitives import serialization, hashes, hmac # Serialização de chaves, funções hash e HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Derivação de chaves (PBKDF2)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Criptografia simétrica (AES-CBC, etc.)
import os # Utilitários do sistema (ex: geração de bytes aleatórios)

# ----- Parâmetros DH fixos e compatíveis -----
parameters_numbers = dh.DHParameterNumbers(
    p=int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
    ),
    g=2
)
parameters = parameters_numbers.parameters(default_backend())

# ----- Geração da chave privada DH -----
def generate_private_key():
    return parameters.generate_private_key()

# ----- Derivação de chaves (AES + HMAC) -----
def derive_keys(shared_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key_material = kdf.derive(shared_key)
    key_aes = key_material[:32]
    key_hmac = key_material[32:]
    return key_aes, key_hmac

# ----- Descriptografia AES CBC -----
def decrypt_message(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_len]
    return plaintext

# ----- HMAC -----
def create_hmac_tag(key_hmac, data):
    h = hmac.HMAC(key_hmac, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def verify_hmac_tag(key_hmac, data, received_tag):
    h = hmac.HMAC(key_hmac, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(received_tag)
        return True
    except Exception:
        return False
