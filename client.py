import requests
import socket
import Messages
import RSA_Helper as RSA
import AES_Helper as AES
import Crypto.PublicKey.RSA
import os

sign_keys =	{
    "Alice": "Alice_public_sign_key.pem",
    "Bob__": "Bob___public_sign_key.pem",
    "Carol": "Carol_public_sign_key.pem",
    "dummy": "dummy_public_sign_key.pem",
    "Serve": "Server_public_sign_key.pem"
} ## Need to be exported to a file

def main():
    print("Welcome to the most secure multi chat application!")

    name = ""
    while len(name) != 5:
        name = input("Please enter your name(exactly 5 character): ")

    # ip = input("Please enter the IP address of the secure server: ")
    # port = input("Please enter the port number of the secure server: ")
    ip = "localhost"
    port = "8080"

    sender = name
    # import own keys
    try:
        rsa_key = RSA.import_key(sender + "_rsa_key.pem")
        sign_key = RSA.import_key(sender + "_sign_key.pem")
    except: #only for debug
        rsa_key = RSA.import_key("keypair.pem")
        sign_key = RSA.import_key("keypair.pem")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))

    print("Connected to server\n")

    #initialize the Connection
    init = Messages.create_INI_message(rsa_key.publickey(), sign_key, sender)
    s.sendall(init)
    s.settimeout(5)
    while True:
        try:
            data = s.recv(4096)
            mes = Messages.Message()
            mes.process_message(data, None, sign_keys)
            if mes.msgtype == "INI" and mes.sender == "Serve":
                aes_key = AES.generate_key()
                print("DONE")
                break
            if mes.msgtype == "KEY":
                print("KEYWAIT")
                aes_key = mes.msg.encode('utf-8')
                break
        except:
            continue
        # elif mes.msgtype == "INI" and mes.validity == True:
    #     print("ELSE")
    #     pass
    s.settimeout(2)

    while True:

        try:
            print("wait")
            data = s.recv(4096)
            print("stsh")
            mes = Messages.Message()
            mes.process_message(data, aes_key, sign_keys)
            print(mes.validity)
            print(mes.sender)
            print(mes.msgtype)
            if mes.msgtype == "INI":
                print("in")
                data = Messages.create_KEY_message(aes_key, Crypto.PublicKey.RSA.import_key(mes.msg.decode('utf-8')), sign_key, sender)
                s.sendall(data)
                print("KEYSENT")


        except:
            continue

        print('Received', repr(data))

        msg = input("input: ")

        if msg == "END_CONN":
            print("Connection is closed.")
            break

        s.sendall(msg.encode('utf-8'))


    s.shutdown(socket.SHUT_RDWR)
    s.close()

main()