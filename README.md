# Servidor de Chat com Suporte a Criptografia

## Descrição

Este projeto implementa um servidor de chat que suporta comunicação criptografada entre clientes e o servidor. A criptografia é realizada utilizando chaves assimétricas (ECC - Elliptic Curve Cryptography) para a troca segura de chaves e AES (Advanced Encryption Standard) para a criptografia das mensagens. O sistema também inclui assinaturas digitais para garantir a autenticidade das mensagens.

## Tecnologias Utilizadas

- **Linguagem de Programação**: Python
- **Bibliotecas/Frameworks**:
  - `socket`: Para comunicação em rede.
  - `threading`: Para suportar múltiplos clientes simultaneamente.
  - `tkinter`: Para a interface gráfica do chat.
  - `cryptography`: Para implementação de criptografia (ECC, AES, HKDF).

## Como Executar


  ### Requisitos

- Python 3.x instalado.
- Biblioteca `cryptography` instalada.

