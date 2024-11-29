import tkinter as tk
from tkinter import scrolledtext
from tkinter import simpledialog
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys

key = b"specificKey__Msg"

def receive_messages(clientSocket, text_widget):
    while True:
        try:
            data = clientSocket.recv(1024).decode('utf-8')
            if data == "Nickname":
                if nickname:
                    cipher = AES.new(key, AES.MODE_CBC)
                    ciphertext = cipher.iv + cipher.encrypt(pad(nickname.encode(), AES.block_size))
                    clientSocket.send(ciphertext)
            else:
                update_text_widget(data, text_widget)
        except Exception as e:
            update_text_widget(f"Error: {e}", text_widget)
            break

def send_message(entry_field, clientSocket, nickname):
    msg = entry_field.get()
    if msg:
        message = f"{nickname} : {msg}"
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.iv + cipher.encrypt(pad(message.encode(), AES.block_size))
        clientSocket.send(ciphertext)
        entry_field.delete(0, tk.END)

def update_text_widget(message, text_widget):
    text_widget.config(state=tk.NORMAL)
    text_widget.insert(tk.END, message + '\n')
    text_widget.yview(tk.END)
    text_widget.config(state=tk.DISABLED)

def on_closing(clientSocket, root):
    try:
        clientSocket.close()
    except:
        pass
    finally:
        root.destroy()
        sys.exit(0)

global nickname
root = tk.Tk()
root.title("Chat Client")

text_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED, width=60, height=20)
text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

entry_field = tk.Entry(root, width=40)
entry_field.pack(side=tk.LEFT, padx=(5, 10), pady=5, fill=tk.X, expand=True)

send_button = tk.Button(root, text="Send", command=lambda: send_message(entry_field, clientSocket, nickname))
send_button.pack(side=tk.RIGHT, pady=5)

nickname = simpledialog.askstring("Nickname", "Enter your nickname:")

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# host_name = "nitishServer.pythonanywhere.com"
host_name = "127.0.0.1"
port = 12345
clientSocket.connect((host_name, port))

receive_thread = threading.Thread(target=receive_messages, args=(clientSocket, text_widget))
receive_thread.start()

root.protocol("WM_DELETE_WINDOW", lambda: on_closing(clientSocket, root))
root.mainloop()
