# server.py
import socket
import threading
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Gerar chave privada do servidor
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()

# Armazenar chave pública em formato serializado
server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

clients = {}

def encrypt_message(public_key, message):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(private_key, encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

def handle_client(client_socket, addr):
    log_message(f"[NEW CONNECTION] {addr} connected.")
    
    # Enviar chave pública do servidor
    client_socket.send(server_public_pem)
    
    # Receber chave pública do cliente
    client_public_pem = client_socket.recv(4096)
    client_public_key = serialization.load_pem_public_key(client_public_pem)
    
    clients[addr] = (client_socket, client_public_key)
    
    while True:
        try:
            encrypted_msg = client_socket.recv(4096)
            if not encrypted_msg:
                break
            decrypted_msg = decrypt_message(server_private_key, encrypted_msg)
            log_message(f"[{addr}] {decrypted_msg}")
            broadcast(encrypted_msg, client_socket)
        except Exception as e:
            print(f"Error: {e}")
            break
    log_message(f"[DISCONNECTED] {addr} disconnected.")
    clients.pop(addr, None)
    client_socket.close()

def broadcast(message, sender_socket=None):
    for addr, (client, public_key) in clients.items():
        if client != sender_socket:
            try:
                encrypted_message = encrypt_message(public_key, message.decode())
                client.send(encrypted_message)
            except:
                client.close()
                clients.pop(addr, None)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5555))
    server.listen(5)
    log_message("[LISTENING] Server is running on port 5555")
    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

def send_from_gui():
    message = entry.get()
    if message:
        broadcast(message.encode())
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
