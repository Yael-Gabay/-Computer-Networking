import numbers
import argparse
import socket
import time
import _socket
import threading
TCP_CONGESTION = 13
ID1 = 3411
ID2 = 1109
#
# rec_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.getaddrinfo('localhost', 9999)
port = 9999
host_name = "127.0.0.1"
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as rec_soc:
    # rec_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        rec_soc.bind((host_name, port))
    except Exception as e:
        print(e)
        rec_soc.close()


    rec_soc.listen(3)    # listening to new connections
    while True:
        print('awaiting connection... ctr + c to stop')
        try:
            sender_socket, addr = rec_soc.accept()  # waits for a new connection with the sender
        except KeyboardInterrupt:
            print('stopped by user')
            break
        print('connection obtained')
        while True: # while the sender is connected
            text_file2 = open('received2.txt', 'wb')
            text_file1 = open('received1.txt', 'wb')
            rec_soc.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, b'cubic')
            curr = rec_soc.getsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, 32)
            print(curr.decode())  # should print cubic

            chunk = sender_socket.recv(2048)
            start = time.time()
            while chunk[-1] != 0:  # while not end of file
                text_file1.write(chunk)
                chunk = sender_socket.recv(2048)
            end = time.time()
            print('time elapsed 1st part: ', end - start)
            text_file1.write(chunk[:-5])
            text_file1.close()
            # done writing to file
            xor = ID1 ^ ID2
            sender_socket.send(xor.to_bytes(5, byteorder='big'))  # send authentication to sender
            rec_soc.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, b'reno')
            curr = rec_soc.getsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, 32)
            print(curr.decode())  # should print reno

            chunk2 = sender_socket.recv(2048)
            start = time.time()
            while chunk2[-1] != 0:
                text_file2.write(chunk2)
                chunk2 = sender_socket.recv(2048)
            sender_socket.send(xor.to_bytes(5, byteorder='big'))
            text_file2.write(chunk[:-5])
            end = time.time()
            print('time elapsed 2nd part: ', end - start)
            # sender_socket.send(b'ack')  # send authentication to sender
            text_file2.close()
            cont = sender_socket.recv(2048)
            print('con', cont)
            if cont == xor.to_bytes(5, byteorder='big'):
                print('receiving again')
            else:
                break
        break
