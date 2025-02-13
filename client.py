# client.py
import socket
import threading
import tkinter as tk

def receive_messages(client):
    while True:
        try:
            msg = client.recv(1024).decode('utf-8')
            log_message(msg)
        except:
            log_message("Disconnected from server.")
            break

def send_message():
    message = entry.get()
    if message:
        client.send(message.encode('utf-8'))
        entry.delete(0, tk.END)

def log_message(msg):
    chat_log.insert(tk.END, msg + '\n')
    chat_log.yview(tk.END)

def start_client():
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 5555))
    
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


