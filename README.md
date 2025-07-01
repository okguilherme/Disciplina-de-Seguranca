# Disciplina-de-Seguran-a

# 🔐 Servidor Seguro

Este projeto implementa um **servidor seguro** que realiza comunicação criptografada com um cliente, utilizando uma combinação de:

- 📡 **Sockets TCP**
- 🔑 **Troca de chaves Diffie-Hellman (DH)**
- ✍️ **Assinatura digital com ECDSA**
- 🧂 **Derivação de chaves com salt**
- 🔒 **Criptografia simétrica AES + HMAC para integridade**

## 🧠 Objetivo

O sistema foi desenvolvido para fins educacionais na disciplina de **Segurança**, com o intuito de demonstrar:

- **Autenticidade** com assinaturas digitais (ECDSA)
- **Sigilo** com Diffie-Hellman + AES
- **Integridade** com HMAC
- **Proteção contra ataques do tipo MITM**
