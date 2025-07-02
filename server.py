import socket
import threading
import requests
import time

# Importando funções auxiliares do utils.py
from utils import (
    derive_keys, decrypt_message, verify_hmac_tag, parameters
)

from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives import hashes, serialization

HOST = '127.0.0.1'  # Endereço IP do servidor (localhost)
PORT = 5000         # Porta para escutar conexões

print("[SERVIDOR] Servidor iniciado.")

# Função que lida com a conexão com um cliente
def handle_client(conn, addr):
    print(f"[SERVIDOR] Conexão Estabelecida")

    try:
        # Recebendo A, assinatura e nome do cliente
        received = conn.recv(4096)
        A_bytes, sig_A, username_cliente = received.split(b"|||")
        A = int(A_bytes.decode())
        print(f"\n[SERVIDOR] Recebido A e assinatura de {username_cliente.decode()}")

        # Baixando a chave pública do cliente do GitHub
        pub_key_url = "https://raw.githubusercontent.com/okguilherme/Disciplina-de-Seguranca/refs/heads/main/key/cliente_publico.pem"
        print(f"\n[SERVIDOR] Baixando chave pública PEM do cliente")
        time.sleep(3)

        response = requests.get(pub_key_url)
        if response.status_code != 200:
            raise Exception("Erro ao baixar chave pública do cliente.")
        pub_key_pem = response.content

        # Carregando a chave pública e verificando a assinatura recebida
        client_pub_key = serialization.load_pem_public_key(pub_key_pem)
        client_pub_key.verify(sig_A, A_bytes + username_cliente, ec.ECDSA(hashes.SHA256()))
        print("\n[SERVIDOR] Assinatura do cliente verificada.")
        time.sleep(3)

        # Gerando chave privada DH do servidor e calculando B
        print("\n[SERVIDOR] Gerando B...")
        time.sleep(3)
        b = parameters.generate_private_key()  # Chave privada (do servidor)
        B = b.public_key().public_numbers().y  # Obtém o valor de B
        B_bytes = str(B).encode()

        # Carregando a chave privada do servidor para assinar B
        priv_key_url = "https://raw.githubusercontent.com/okguilherme/Disciplina-de-Seguranca/refs/heads/main/key/servidor.pem"
        priv_key_pem = requests.get(priv_key_url).content
        private_key_ecdsa = serialization.load_pem_private_key(priv_key_pem, password=None)
        username_servidor = b"okguilherme"

        # Assinando B + nome do servidor
        sig_B = private_key_ecdsa.sign(B_bytes + username_servidor, ec.ECDSA(hashes.SHA256()))

        # Enviando B, assinatura e nome do servidor para o cliente
        conn.sendall(B_bytes + b"|||" + sig_B + b"|||" + username_servidor)
        print("\n[SERVIDOR] Enviando B, assinatura ao cliente.")

        # Criando objeto da chave pública do cliente a partir de A
        peer_pub = dh.DHPublicNumbers(A, parameters.parameter_numbers()).public_key()
        shared_secret = b.exchange(peer_pub)  # Realizando troca de chaves DH
        S = int.from_bytes(shared_secret, byteorder='big')  # Convertendo o segredo compartilhado em inteiro

        print(f"\n[SERVIDOR] DH Calculado")
        time.sleep(3)
        print(f"\n [SERVIDOR] Valor de S: {S}")
        time.sleep(3)

        # Enviando salt para o cliente
        salt = b'salt_seguro'
        conn.sendall(salt)

        # Derivando chaves AES e HMAC a partir do segredo compartilhado e salt
        key_aes, key_hmac = derive_keys(shared_secret, salt)
        print("\n[SERVIDOR] Chaves derivadas com sucesso.")

        # Recebendo mensagem criptografada com IV e HMAC
        packet = conn.recv(8192)
        if not packet:
            return

        hmac_tag = packet[:32]        # Primeiro 32 bytes: HMAC
        iv = packet[32:48]            # Próximos 16 bytes: IV
        ciphertext = packet[48:]      # Restante: mensagem criptografada

        print("\n[SERVIDOR] Verificando HMAC...")
        time.sleep(3) 
        # Verificando integridade e autenticidade da mensagem
        if verify_hmac_tag(key_hmac, iv + ciphertext, hmac_tag):
            print("\n[SERVIDOR] HMAC válido.")
            time.sleep(3)
            print(f"\n[SERVIDOR] Mensagem criptografada recebida: {ciphertext.hex()}")
            time.sleep(3)
            print("\n[SERVIDOR] Descriptografando...")
            time.sleep(3)
            plaintext = decrypt_message(key_aes, iv, ciphertext)
            print(f"\n[SERVIDOR] Mensagem recebida: {plaintext.decode()}")
        else:
            print("\n[SERVIDOR] HMAC inválido. Mensagem rejeitada.")

    except Exception as e:
        print(f"[SERVIDOR] Erro: {e}")
    finally:
        conn.close()
        print(f"\n[SERVIDOR] Conexão encerrada")

# Função principal que inicia o servidor e aguarda conexões
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"[SERVIDOR] Escutando...")
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

# Executando o servidor
if __name__ == "__main__":
    main()
