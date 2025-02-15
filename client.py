import socket
import threading
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import sys

# Gerar chave privada do cliente (ECC)
client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()

# Armazenar chave pública em formato serializado
client_public_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Variável global para armazenar a chave pública do servidor
server_public_key = None
shared_key = None
client = None

def derive_shared_key(private_key, peer_public_key):
    # Gerar chave compartilhada usando ECDH
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    # Derivar uma chave AES usando HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def encrypt_message(key, message):
    # Usar AES para criptografar a mensagem
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message) + encryptor.finalize()  # Removido .encode()
    return iv + encryptor.tag + encrypted

def decrypt_message(key, encrypted_message):
    # Usar AES para descriptografar a mensagem
    iv = encrypted_message[:16]
    tag = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def sign_message(private_key, message):
    # Assinar a mensagem com a chave privada ECC
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(public_key, message, signature):
    # Verificar a assinatura com a chave pública ECC
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False

def receive_messages(client):
    global shared_key, server_public_key
    while True:
        try:
            encrypted_msg = client.recv(4096)
            if not encrypted_msg:
                break
            decrypted_msg = decrypt_message(shared_key, encrypted_msg)
            
            # Extrair o tamanho da assinatura (primeiros 4 bytes)
            signature_size = int.from_bytes(decrypted_msg[:4], byteorder='big')
            # Extrair a assinatura
            signature = decrypted_msg[4:4 + signature_size]
            # Extrair a mensagem
            message = decrypted_msg[4 + signature_size:]
            
            # Verificar a assinatura
            if verify_signature(server_public_key, message, signature):
                log_message(message.decode())
            else:
                log_message("Assinatura inválida!")
        except Exception as e:
            log_message(f"Disconnected from server. Error: {e}")
            break

def send_message():
    global shared_key, client
    message = entry.get()
    if message and shared_key:
        if message == "end":
            # Fechar a conexão com o servidor
            client.close()
            log_message("[CLIENT] Connection closed.")
            tk_root.quit()  # Fechar a interface gráfica
            sys.exit()  # Encerrar o programa
            return
        
        # Assinar a mensagem
        signature = sign_message(client_private_key, message.encode())
        
        # Codificar o tamanho da assinatura (4 bytes)
        signature_size = len(signature).to_bytes(4, byteorder='big')
        
        # Concatenar tamanho da assinatura, assinatura e mensagem
        signed_message = signature_size + signature + message.encode()
        
        # Criptografar a mensagem assinada
        encrypted_message = encrypt_message(shared_key, signed_message)
        
        # Enviar a mensagem criptografada
        client.send(encrypted_message)
        entry.delete(0, tk.END)
        
def log_message(msg):
    chat_log.insert(tk.END, msg + '\n')
    chat_log.yview(tk.END)

def start_client():
    global client, server_public_key, shared_key
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 5555))
    
    # Receber chave pública do servidor
    server_public_pem = client.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_public_pem)
    
    # Enviar chave pública do cliente
    client.send(client_public_pem)
    
    # Gerar chave compartilhada
    shared_key = derive_shared_key(client_private_key, server_public_key)
    
    thread = threading.Thread(target=receive_messages, args=(client,))
    thread.daemon = True
    thread.start()
    
    tk_root.mainloop()

# Start GUI for client
tk_root = tk.Tk()
tk_root.title("Client Chat")
chat_log = tk.Text(tk_root, height=20, width=50)
chat_log.pack()
entry = tk.Entry(tk_root, width=50)
entry.pack()
btn_send = tk.Button(tk_root, text="Send", command=send_message)
btn_send.pack()

if __name__ == "__main__":
    start_client()