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
}

aes_key = AES.generate_key() #Just so the program not crashing, not using really
sender = "Serve"
sign_key = RSA.import_key("Server_sign_key.pem")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.setblocking(False)
s.settimeout(1)
s.bind(('localhost', 8080))
s.listen(1)
# conn, addr = s.accept()
print("1")

conn = []

while 1:
    print("2")
    try:
        c, addr = s.accept()
        data_thread = Threads.data_reader(c, True)
        data_thread.start()
        conn.append(data_thread)
        if len(conn) == 0:
            continue
        else:
            print("len", len(conn))
    except:
            pass
    print("3")

    for i in range(0, len(conn)):
        print("for", i)
        # Close connection
        if conn[i].end == True:
            print("Del")
            conn[i].socket.shutdown(socket.SHUT_RDWR)
            conn[i].socket.close()
            conn[i].active = False
            conn[i].join()
            del conn[i]
            break
        try:
            # data = data_thread.data_list.pop(0)
            data = conn[i].data_list.pop(0)
            mes = Messages.Message()
            if data[0:3] == "DAT".encode('utf-8'):
                print("DAT CAME")
                for j in range(len(conn)):
                    if i != j:
                        conn[j].socket.sendall(data)
            else:
                mes.process_message(data, aes_key, sign_keys)
                print(mes.sender)
                print(mes.validity)
                print(mes.msgtype)

                # Process INI messages
                if mes.msgtype == "INI":
                    print("init")
                    if len(conn) == 1:
                        data = Messages.create_INI_message(sign_key.publickey(), sign_key, sender)
                        conn[i].socket.sendall(data)
                    else:
                        conn[0].socket.sendall(data)
                        print("else")
                elif mes.msgtype == "KEY":
                    print("key")
                    conn[len(conn)-1].socket.sendall(data)
                elif mes.msgtype =="DAT":
                    print("DAT came")
                    pass
                # elif:
                else:
                    print("Back where it come from")
                    conn[i].socket.sendall(data)
        except:
            continue



# conn.shutdown(socket.SHUT_RDWR)
# conn.close()