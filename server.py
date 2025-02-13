# server.py
import socket
import threading
import tkinter as tk
from flask import Flask, request, jsonify

app = Flask(__name__)
clients = []

def handle_client(client_socket, addr):
    log_message(f"[NEW CONNECTION] {addr} connected.")
    clients.append(client_socket)
    while True:
        try:
            msg = client_socket.recv(1024).decode('utf-8')
            if not msg:
                break
            log_message(f"[{addr}] {msg}")
            broadcast(msg, client_socket)
        except:
            break
    log_message(f"[DISCONNECTED] {addr} disconnected.")
    clients.remove(client_socket)
    client_socket.close()

def broadcast(message, sender_socket=None):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message.encode('utf-8'))
            except:
                client.close()
                clients.remove(client)

@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    message = data.get('message', '')
    if message:
        broadcast(f"[SERVER] {message}")
        log_message(f"[SERVER] {message}")
        return jsonify({"status": "Message sent"})
    return jsonify({"error": "No message provided"}), 400

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
        broadcast(f"[SERVER] {message}")
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

if __name__ == '__main__':
    app_thread = threading.Thread(target=lambda: app.run(port=5000))
    app_thread.daemon = True
    app_thread.start()
    tk_root.mainloop()