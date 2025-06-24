import socket
from utils import (
    generate_dh_key_pair, serialize_public_key, deserialize_public_key,
    derive_keys, encrypt_message, create_hmac_tag, parameters
)


HOST = '127.0.0.1'
PORT = 65432


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print("Conectado ao servidor.")

    # 1. Gera chave DH do cliente
    client_private_key, client_public_key = generate_dh_key_pair()
    client_public_key_pem = serialize_public_key(client_public_key)

    # 2. Envia chave pública DH para o servidor
    client_socket.sendall(client_public_key_pem)
    print("Cliente: Chave pública enviada.")

    # 3. Recebe chave pública DH do servidor
    server_public_key_pem = client_socket.recv(4096)
    server_public_key = deserialize_public_key(server_public_key_pem)
    print("Cliente: Chave pública do servidor recebida.")

    # 4. Calcula segredo compartilhado
    shared_secret = client_private_key.exchange(server_public_key)
    print("Cliente: Segredo compartilhado calculado.")

    # 5. Deriva chaves AES e HMAC
    salt = b'salt_seguro'  # Salt fixo para o exemplo
    key_aes, key_hmac = derive_keys(shared_secret, salt)
    print("Cliente: Chaves derivadas com sucesso.")

    # 6. Envia mensagens seguras
    try:
        while True:
            msg = input("Digite uma mensagem (ou 'sair'): ")
            if msg.lower() == 'sair':
                break

            iv, ciphertext = encrypt_message(key_aes, msg.encode())
            data_to_hmac = iv + ciphertext
            hmac_tag = create_hmac_tag(key_hmac, data_to_hmac)

            packet = hmac_tag + iv + ciphertext
            client_socket.sendall(packet)
            print("Mensagem enviada.")

    except Exception as e:
        print(f"Erro: {e}")
    finally:
        print("Encerrando conexão.")
        client_socket.close()


if __name__ == "__main__":
    main()
