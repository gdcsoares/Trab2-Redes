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

- Python 3 com tkinter instalado.
- Biblioteca `cryptography` instalada.

### Instruções de Execução

1. Clone o repositório (se aplicável):
   ```bash
   git clone https://github.com/gdcsoares/Trab2-Redes.git

2. Verifique se o `tkinter` está instalado:  
   ```bash
   python -m tkinter

    Caso não esteja, execute:

     `bash
     sudo apt update  
     sudo apt install python3-tk  

3. Instale as dependências:
   ```bash
   pip install cryptography

4. Execute o servidor:
   ```bash
   python server.py

5. Execute o cliente:
   ```bash
   python client.py

## Como Testar

1. Inicie o servidor e o cliente.

2. No cliente, digite uma mensagem no campo de texto e clique em "Send".

3. A mensagem será criptografada, assinada e enviada ao servidor. A versão criptografada da mensagem pode ser vista no terminal como forma de teste.

4. O servidor descriptografa a mensagem, verifica a assinatura e exibe a mensagem no log.

5. O servidor pode enviar mensagens de volta ao cliente, que também serão criptografadas e assinadas.

6. Para encerrar a conexão, digite "end" no campo de texto de cada cliente (ou feche a interface) e depois escreva "end" no campo do servidor.

