import socket
import Messages
import RSA_Helper as RSA
import Threads
import AES_Helper as AES


sign_keys =	{
    "Alice": "Alice_public_sign_key.pem",
    "Bob__": "Bob___public_sign_key.pem",
    "Carol": "Carol_public_sign_key.pem",
    "dummy": "dummy_public_sign_key.pem",
    "Serve": "Server_public_sign_key.pem"
}## Need to be exported to a file

aes_key = AES.generate_key() #Just so the program not crashing, not using really
sender = "Serve"
sign_key = RSA.import_key("Server_sign_key.pem")

#Make socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
s.bind(('localhost', 8080))
s.listen(1)

conn = []

while 1:
    try:
        #Is there any new client who wants to connect?
        c, addr = s.accept()
        #If yes, then he got an own thread
        data_thread = Threads.data_reader(c, True)
        data_thread.start()
        conn.append(data_thread)
        #if no clients, we just wait for connection
        if len(conn) == 0:
            continue
        else:
            pass
    except:
            pass

    for i in range(0, len(conn)):
        # Close connection
        if conn[i].end == True:
            conn[i].socket.shutdown(socket.SHUT_RDWR)
            conn[i].socket.close()
            conn[i].active = False
            conn[i].join()
            del conn[i]
            break
        try:
            #wait for messages
            data = conn[i].data_list.pop(0)
            mes = Messages.Message()
            #Then process them

            #DAT is forwarded instantly to everybody
            if data[0:3] == "DAT".encode('utf-8'):
                for j in range(len(conn)):
                    if i != j:
                        conn[j].socket.sendall(data)
            #Key is forwarded to the last connector
            elif data[0:3] == "KEY".encode('utf-8'):
                conn[len(conn) - 1].socket.sendall(data)
            else:
                mes.process_message(data, aes_key, sign_keys)

                # Process INI messages
                if mes.msgtype == "INI":
                    #If he is the first, then we send new INI back to sign them to generate own key
                    if len(conn) == 1:
                        data = Messages.create_INI_message(sign_key.publickey(), sign_key, sender)
                        conn[i].socket.sendall(data)
                    #If not, then the INI is forwarded to the first connector
                    else:
                        conn[0].socket.sendall(data)
                #process END
                elif mes.msgtype =="END":
                    conn[i].socket.shutdown(socket.SHUT_RDWR)
                    conn[i].socket.close()
                    conn[i].active = False
                    conn[i].join()
                    pass
                # elif:
                else:
                    #if he is not validated, the we send his message back to him
                    conn[i].socket.sendall(data)
        except:
            continue



# conn.shutdown(socket.SHUT_RDWR)
# conn.close()