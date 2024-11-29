import socket
import threading
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b"specificKey__Msg"

try:
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except:
    print("Unable to create socket")

hostName = "127.0.0.1"
port = int(os.environ.get('PORT', 12345))
serverSocket.bind((hostName, port))
serverSocket.listen()

clients = []
nicknames = []

def sendInfo(payLoad):
    for client in clients:
        client.send(bytes(payLoad, 'utf-8'))

def handleClients(clientSocket):
    while True:
        try:
            data = clientSocket.recv(1024)
            iv = data[:16]
            ciphertext = data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            message = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
            sendInfo(message)
        except:
            index = clients.index(clientSocket)
            clients.remove(clientSocket)
            clientSocket.close()
            nickname = nicknames[index]
            nicknames.remove(nickname)
            sendInfo('{} has left the chat!'.format(nickname))
            print("{} has disconnected".format(nickname))
            break

def receive():
    while True:
        clientSocket, addr = serverSocket.accept()
        print("Connected to " + str(addr))
        clientSocket.send(bytes("Nickname", 'utf-8'))
        nickname = clientSocket.recv(1024)
        iv = nickname[:16]
        ciphertext = nickname[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        nickname = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        clients.append(clientSocket)
        nicknames.append(nickname)
        sendInfo('{} has joined the chat'.format(nickname))

        thread = threading.Thread(target=handleClients, args=(clientSocket,))
        thread.start()

receive()
