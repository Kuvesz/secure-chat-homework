import socket
import Messages
import RSA_Helper as RSA
import AES_Helper as AES
import Crypto.PublicKey.RSA
import Threads
# import threading

sign_keys =	{
    "Alice": "Alice_public_sign_key.pem",
    "Bob__": "Bob___public_sign_key.pem",
    "Carol": "Carol_public_sign_key.pem",
    "dummy": "dummy_public_sign_key.pem",
    "Serve": "Server_public_sign_key.pem"
} ## Need to be exported to a file

msg_list = []

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
    except: #only for debug, and the program dont crash, cannot decode anything with theese keys
        rsa_key = RSA.import_key("keypair.pem")
        sign_key = RSA.import_key("keypair.pem")

    #Make socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))

    print("Connected to server\n")

    #initialize the Connection
    init = Messages.create_INI_message(rsa_key.publickey(), sign_key, sender)
    s.sendall(init)

    #Start user input monitoring helper
    input_thread = Threads.input_reader(True)
    input_thread.start()


    #wait for the response
    #If first client, the the server answer with init
    #If not, then another client will send the key
    while True:
        data = s.recv(4096)
        mes = Messages.Message()
        mes.process_message(data, None, sign_keys)
        if mes.msgtype == "INI" and mes.sender == "Serve":
            aes_key = AES.generate_key()
            break
        elif mes.msgtype == "KEY":
            aes_key = mes.msg
            break

    print("Init Done\n")

    #Start socket monitoring thread
    data_thread = Threads.data_reader(s, True)
    data_thread.start()

    while True:

        try:
            #Waiting for messages
            data = data_thread.data_list.pop(0)
            mes = Messages.Message()
            #and process them
            mes.process_message(data, aes_key, sign_keys)
            if mes.msgtype == "INI":
                #If INI, then we send the key
                data = Messages.create_KEY_message(aes_key, Crypto.PublicKey.RSA.import_key(mes.msg.encode('utf-8')), sign_key, sender)
                s.sendall(data)
                #And broadcast, that there is a new participant
                data = Messages.create_DAT_message(mes.sender + " connected.", aes_key, sign_key, sender)
                print(mes.sender + " connected.")
                s.sendall(data)
            #If DAT, then we write the message to the console
            if mes.msgtype == "DAT":
                print(mes.sender + ": " + mes.msg)
            #If key, then we use it as AES key
            if mes.msgtype == "KEY":
                aes_key = mes.msg
        except:
            pass

        try:
            msg = input_thread.input_list.pop(0)
            #END_CONN is the quit message
            if msg == "END_CONN":
                print("Connection is closed.\n")
                break
            #Send out the user input
            data = Messages.create_DAT_message(msg, aes_key, sign_key, sender)
            s.sendall(data)
        except:
            pass

        if data_thread.end == True:
            print("Server closed connection.\n")
            break

    #Terminate threads
    input_thread.active = False
    data_thread.active = False
    input_thread.join()
    data_thread.join()

    #Terminate socket
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    return

main()