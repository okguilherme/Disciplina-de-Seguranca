import socket
import threading
from utils import (
    generate_dh_key_pair, serialize_public_key, deserialize_public_key,
    derive_keys, encrypt_message, decrypt_message, create_hmac_tag, verify_hmac_tag,
    parameters
)
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.exceptions import InvalidTag


HOST = '127.0.0.1'
PORT = 65432
print("iniciado")

def handle_client(conn, addr):
    print(f"Conexão estabelecida com {addr}")

    try:
        # 1. Recebe chave pública DH do cliente
        client_public_key_pem = conn.recv(4096)
        client_public_key = deserialize_public_key(client_public_key_pem)
        print("Servidor: Chave pública do cliente recebida.")

        # 2. Gera chave DH do servidor
        server_private_key, server_public_key = generate_dh_key_pair()
        server_public_key_pem = serialize_public_key(server_public_key)

        # 3. Envia chave pública DH do servidor
        conn.sendall(server_public_key_pem)
        print("Servidor: Chave pública enviada ao cliente.")

        # 4. Calcula segredo compartilhado
        shared_secret = server_private_key.exchange(client_public_key)
        print("Servidor: Segredo compartilhado calculado.")

        # 5. Deriva chaves AES e HMAC
        salt = b'salt_seguro'  # Salt fixo para o exemplo
        key_aes, key_hmac = derive_keys(shared_secret, salt)
        print("Servidor: Chaves derivadas com sucesso.")

        # 6. Comunicação segura
        while True:
            received_packet = conn.recv(8192)
            if not received_packet:
                break

            hmac_tag = received_packet[:32]
            iv = received_packet[32:48]
            ciphertext = received_packet[48:]

            data_to_verify = iv + ciphertext
            if verify_hmac_tag(key_hmac, data_to_verify, hmac_tag):
                plaintext = decrypt_message(key_aes, iv, ciphertext)
                print(f"Mensagem recebida: {plaintext.decode()}")
            else:
                print("HMAC inválido. Mensagem rejeitada.")
                break

    except (dh.DHKeyExchangeError, InvalidTag) as e:
        print(f"Erro: {e}")
    except Exception as e:
        print(f"Erro inesperado: {e}")
    finally:
        print(f"Conexão com {addr} encerrada.")
        conn.close()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Servidor escutando em {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


if __name__ == "__main__":
    main()
