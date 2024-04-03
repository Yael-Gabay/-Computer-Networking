import socket

RECEIVER_PORT = 9999  # The port that the Receiver listens to.
RECEIVER_IP = "127.0.0.1"  # Receiver's IP for the connection
TCP_CONGESTION = 13  # For the cc
BUFFER_SIZE = 2000000  # 2MB
BUFFER_HALF_SIZE = 1000000  # Half of 2MB
FILE_NAME = "2MB.txt"  # Name of the file
# For the xor authentication:
ID1 = 3411
ID2 = 1109

file = bytearray(BUFFER_SIZE)  # Array for reading the file

# Read file
try:
    with open(FILE_NAME, "rb") as file_ptr:
        file_ptr.readinto(file)  # Reading the file FILE_NAME into 'file'.
except IOError:
    print("File can't be opened.")
    exit()

# Create TCP Connection
mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    receiver_address = (RECEIVER_IP, RECEIVER_PORT)
    mySocket.connect(receiver_address)
except ConnectionError:
    print("Could not connect to the receiver.")
    exit()

print("Connected.")

while True:
    # Change CC to Cubic
    ccFlag = mySocket.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, b'cubic')
    if ccFlag == -1:
        print("Failed to set socket option.")
    else:
        print("CC algorithm is: cubic")

    # Send First Half
    bytes_sent = 0
    flag = True
    while bytes_sent < BUFFER_HALF_SIZE:
        bytes = mySocket.send(file[bytes_sent:bytes_sent+BUFFER_HALF_SIZE])
        if bytes == -1:
            print("Failed to send data.")
            flag = False
            break
        bytes_sent += bytes
    if flag:
        print("The first half of the file has been sent.")
        mySocket.send((0).to_bytes(5, byteorder='big'))

    # Receive Authentication
    msg = mySocket.recv(5)
    xor = (ID1 ^ ID2).to_bytes(5, byteorder='big')
    if xor == msg:
        print("Authentication succeeded.")
    else:
        print("Aunthentication failed.")

    # Change CC To Reno
    if mySocket.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, b'reno') == -1:
        print("Failed to set socket option.")
    else:
        print("CC algorithm is: reno")

    # Send Second Half
    flag = True
    while bytes_sent < BUFFER_SIZE:
        bytes = mySocket.send(file[bytes_sent:bytes_sent+BUFFER_HALF_SIZE])
        if bytes == -1:
            print("Failed to send data.")
            flag = False
            break
        bytes_sent += bytes

    if flag:
        print("The second half of the file has been sent.")
        mySocket.send((0).to_bytes(5, byteorder='big'))
    msg = mySocket.recv(5)
    if xor == msg:
        print("Authentication succeeded.")
    else:
        print("Aunthentication failed.")
    print("Send the file again? Enter y/n.")
    flage = input().strip()
    if flage == 'n':
        mySocket.send(b"exit")  # Send exit message
        break
    else:
        mySocket.send(xor)

    print("~~~~~~")

print("Exiting.")

# Close Connection
mySocket.close()
print("Connection closed.")
