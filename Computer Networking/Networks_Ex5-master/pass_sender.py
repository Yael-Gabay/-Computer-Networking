import socket

HOST = "127.0.0.1"
PORT = 23

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((HOST, PORT))
    command = "Password: 1234567\r\n"
    sock.sendall(command.encode('ascii'))

    response = sock.recv(1024)
    print("Response:", response.decode('utf-8'))

    sock.close()
except KeyboardInterrupt:
    sock.close()
