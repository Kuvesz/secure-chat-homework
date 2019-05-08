import requests
import socket
import os

def main():
    print("Welcome to the most secure multi chat application!")

    name = ""
    while len(name) != 5:
        name = input("Please enter your name(exactly 5 character):")

    ip = input("Please enter the IP address of the secure server:")
    port = input("Please enter the port number of the secure server:")
    url = "http://" + ip + ":" + port
    print(url)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))

    # response = os.system("ping -n 1 " + ip)
    # print(response)

    s.sendall(b'Hello, world')
    data = s.recv(1024)
    s.close()
    print('Received', repr(data))

main()