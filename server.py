import socket
import threading
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
import os
import sys

# Gerar chave privada do servidor (ECC)
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()

# Armazenar chave pública em formato serializado
server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

clients = {}

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

def handle_client(client_socket, addr):
    log_message(f"[NEW CONNECTION] {addr} connected.")
    
    # Enviar chave pública do servidor
    client_socket.send(server_public_pem)
    
    # Receber chave pública do cliente
    client_public_pem = client_socket.recv(4096)
    client_public_key = serialization.load_pem_public_key(client_public_pem)
    
    # Gerar chave compartilhada
    shared_key = derive_shared_key(server_private_key, client_public_key)
    
    clients[addr] = (client_socket, shared_key, client_public_key)
    
    while True:
        try:
            encrypted_msg = client_socket.recv(4096)
            if not encrypted_msg:
                break
            
            # Descriptografar a mensagem
            decrypted_msg = decrypt_message(shared_key, encrypted_msg)
            
            # Extrair o tamanho da assinatura (primeiros 4 bytes)
            signature_size = int.from_bytes(decrypted_msg[:4], byteorder='big')
            
            # Extrair a assinatura
            signature = decrypted_msg[4:4 + signature_size]
            
            # Extrair a mensagem
            message = decrypted_msg[4 + signature_size:]
            
            # Verificar a assinatura
            if verify_signature(client_public_key, message, signature):
                log_message(f"[{addr}] {message.decode()}")
            else:
                log_message(f"[{addr}] Assinatura inválida!")
        except Exception as e:
            print(f"Error: {e}")
            break
    
    log_message(f"[DISCONNECTED] {addr} disconnected.")
    clients.pop(addr, None)
    client_socket.close()

def broadcast(message, sender_socket=None):
    for addr, (client, shared_key) in clients.items():
        if client != sender_socket:
            try:
                client.send(message)
            except:
                client.close()
                clients.pop(addr, None)

def close_all_connections():
    for addr, (client, shared_key, client_public_key) in clients.items():
        client.close()
    clients.clear()
    log_message("[SERVER] All connections closed.")
    sys.exit()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5555))
    server.listen(5)
    log_message("[LISTENING] Server is running on port 5555")
    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

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

def send_from_gui():
    message = entry.get()
    if message:
        if message == 'end':
            close_all_connections()
            return
        for addr, (client, shared_key, client_public_key) in clients.items():
            # Assinar a mensagem
            signature = sign_message(server_private_key, message.encode())
            # Codificar o tamanho da assinatura (4 bytes)
            signature_size = len(signature).to_bytes(4, byteorder='big')
            # Concatenar tamanho da assinatura, assinatura e mensagem
            signed_message = signature_size + signature + message.encode()
            # Criptografar a mensagem assinada
            encrypted_message = encrypt_message(shared_key, signed_message)
            client.send(encrypted_message)
        log_message(f"[SERVER] {message}")
        entry.delete(0, tk.END)

def log_message(msg):
    chat_log.insert(tk.END, msg + '\n')
    chat_log.yview(tk.END)

# Start GUI for server
tk_root = tk.Tk()
tk_root.title("Server Chat")
chat_log = tk.Text(tk_root, height=20, width=50)
chat_log.pack()
entry = tk.Entry(tk_root, width=50)
entry.pack()
btn_send = tk.Button(tk_root, text="Send", command=send_from_gui)
btn_send.pack()

t = threading.Thread(target=start_server)
t.daemon = True
t.start()

tk_root.mainloop()