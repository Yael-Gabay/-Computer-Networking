import socket

# Define the listening address and port
HOST = "127.0.0.1"  # Replace with your IP address
PORT = 23

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind((HOST, PORT))
    sock.listen(2)

    client_socket, client_address = sock.accept()
    print("Client connected:", client_address)

    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        print("Received:", data.decode('utf-8'))

    client_socket.close()
except KeyboardInterrupt:
    sock.close()

sock.close()
