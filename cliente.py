# Importações de bibliotecas para comunicação, criptografia, assinatura, etc.
import socket
import secrets
import requests
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Importando os parâmetros p e g para o Diffie-Hellman do arquivo utils.py
from utils import parameters

# Pegando os valores de p e g
nums = parameters.parameter_numbers()
p = nums.p
g = nums.g

# Endereço IP e porta do servidor
HOST = '127.0.0.1'
PORT = 5000

# Identificadores das partes (cliente e servidor)
username_cliente = b"Wiliene"
username_servidor = b"okguilherme"

# Criando o socket e se conectando ao servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print("\n[CLIENTE] Conectando ao servidor...")
    s.connect((HOST, PORT))
    print("[CLIENTE] Conectado com sucesso.")

    # Gerando a chave privada DH (a) e a chave pública A = g^a mod p
    print("\n[CLIENTE] Gerando A...")
    time.sleep(3)
    a = secrets.randbelow(p)
    A = pow(g, a, p)
    A_bytes = str(A).encode()

    # Baixando a chave privada do cliente para assinar A e o username
    priv_key_url = "https://raw.githubusercontent.com/okguilherme/Disciplina-de-Seguranca/refs/heads/main/key/cliente.pem"
    priv_key_pem = requests.get(priv_key_url).content
    private_key_ecdsa = serialization.load_pem_private_key(priv_key_pem, password=None)

    # Assinando A_bytes + username_cliente com ECDSA
    sig_A = private_key_ecdsa.sign(A_bytes + username_cliente, ec.ECDSA(hashes.SHA256()))
    print(f"\n[CLIENTE] Gerando Assinatura.")
    time.sleep(3)

    # Enviando A, a assinatura e o username para o servidor
    s.sendall(A_bytes + b"|||" + sig_A + b"|||" + username_cliente)
    print("\n[CLIENTE] Enviando A e assinatura para o Servidor.")
    time.sleep(3)

    # Recebendo B (chave pública DH do servidor), a assinatura, e o username do servidor
    data = s.recv(4096)
    if b"|||" not in data:
        print("\n[CLIENTE] ERRO: resposta inesperada:", data)
        exit(1)

    B_bytes, sig_B, username_srv = data.split(b"|||")
    B = int(B_bytes.decode())
    print(f"\n[CLIENTE] Dados recebidos do servidor:")

    # Baixando a chave pública do servidor para verificar a assinatura recebida
    print("\n[CLIENTE] Baixando a chave pública do servidor...")
    time.sleep(3)
    pub_key_url = "https://raw.githubusercontent.com/okguilherme/Disciplina-de-Seguranca/refs/heads/main/key/servidor_publico.pem"
    response = requests.get(pub_key_url)
    if response.status_code != 200:
        print("[CLIENTE] ERRO ao baixar chave pública do servidor.")
        exit(1)
    pub_key_pem = response.content
    server_pub_key = serialization.load_pem_public_key(pub_key_pem)

    # Verificando a assinatura do servidor sobre (B_bytes + username)
    data_to_verify = B_bytes + username_srv
    print(f"\n[CLIENTE] Verificando dados recebidos do servidor...")
    time.sleep(3)
    try:
        server_pub_key.verify(sig_B, data_to_verify, ec.ECDSA(hashes.SHA256()))
        print("\n[CLIENTE] Assinatura do servidor verificada.")
        time.sleep(3)
    except Exception:
        print("[CLIENTE] Assinatura do servidor inválida.")
        exit(1)

    # Calculando o segredo compartilhado S = B^a mod p
    S = pow(B, a, p)
    S_bytes = S.to_bytes((S.bit_length() + 7) // 8, byteorder='big')
    print(f"\n[CLIENTE] DH calculado")
    time.sleep(3)
    print(f"\n[CLIENTE] Valor de S: {S}")
    time.sleep(3)

    # Recebendo o salt do servidor para derivar as chaves com PBKDF2
    salt = s.recv(4096)

    # Derivando duas chaves a partir de S usando PBKDF2 (AES + HMAC)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=salt, iterations=100000)
    key_material = kdf.derive(S_bytes)
    Key_AES = key_material[:32]
    Key_HMAC = key_material[32:]
    print("\n[CLIENTE] Chaves derivadas com sucesso.")
    time.sleep(3)

    # Pegando a mensagem do usuário e aplicando padding para múltiplo de 16 bytes (AES-CBC)
    msg = input("\nDigite uma mensagem para enviar: ").encode()
    pad_len = 16 - (len(msg) % 16)
    padded_msg = msg + bytes([pad_len] * pad_len)

    # Gerando IV e criptografando a mensagem com AES-CBC
    IV = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(Key_AES), modes.CBC(IV))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()

    # Criando um HMAC da mensagem criptografada (IV + ciphertext)
    h = hmac.HMAC(Key_HMAC, hashes.SHA256())
    h.update(IV + ciphertext)
    HMAC_TAG = h.finalize()
     
    #testar confiabilidade/integridade
    hmac_alterado = bytearray(HMAC_TAG)
    hmac_alterado[0] ^= 0xFF  # Inverte o primeiro byte do HMAC
    
    # Enviando o pacote (HMAC + IV + ciphertext) para o servidor
    s.sendall(HMAC_TAG + IV + ciphertext)
    print("\n[CLIENTE] Mensagem enviada com sucesso.")
