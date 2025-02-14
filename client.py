# client.py
import socket
import threading
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Gerar chave privada do cliente
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()

# Armazenar chave pública em formato serializado
client_public_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Variável global para armazenar a chave pública do servidor
server_public_key = None

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
    print(f"Mensagem criptografada recebida: {encrypted_message}")
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    print(f"Mensagem decodificada: {decrypted}")
    return decrypted

def receive_messages(client):
    global server_public_key
    while True:
        try:
            encrypted_msg = client.recv(4096)
            if not encrypted_msg:
                break
            decrypted_msg = decrypt_message(client_private_key, encrypted_msg)
            log_message(decrypted_msg)
        except:
            log_message("Disconnected from server.")
            break

def send_message():
    global server_public_key
    message = entry.get()
    if message and server_public_key:
        encrypted_message = encrypt_message(server_public_key, message)
        client.send(encrypted_message)
        entry.delete(0, tk.END)

def log_message(msg):
    chat_log.insert(tk.END, msg + '\n')
    chat_log.yview(tk.END)

def start_client():
    global client, server_public_key
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 5555))
    
    # Receber chave pública do servidor
    server_public_pem = client.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_public_pem)
    
    # Enviar chave pública do cliente
    client.send(client_public_pem)
    
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