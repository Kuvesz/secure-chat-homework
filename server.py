import socket
import Messages
import RSA_Helper as RSA


sign_keys =	{
    "Alice": "Alice_public_sign_key.pem",
    "Bob__": "Bob___public_sign_key.pem",
    "Carol": "Carol_public_sign_key.pem",
    "dummy": "dummy_public_sign_key.pem",
    "Serve": "Server_public_sign_key.pem"
}

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
        c.settimeout(1)
        conn.append(c)
    except:
        if len(conn) == 0:
            continue
        else:
            print("len", len(conn))
            pass
    print("3")

    for i in range(0, len(conn)):
        print("for", i)
        try:
            data = conn[i].recv(4096)

            # Close connection
            if not data:
                conn[i].shutdown(socket.SHUT_RDWR)
                conn[i].close()
                del conn[i]
                break

            mes = Messages.Message()
            mes.process_message(data, None, sign_keys)
            print(mes.sender)
            print(mes.validity)
            print(mes.msgtype)

            # Process INI messages
            if mes.msgtype == "INI":
                print("init")
                if len(conn) == 1:
                    data = Messages.create_INI_message(sign_key.publickey(), sign_key, sender)
                    conn[i].sendall(data)
                else:
                    conn[0].sendall(data)
                    print("else")
            elif mes.msgtype == "KEY":
                print("key")
                conn[len(conn)-1].sendall(data)
            else:
                conn[i].sendall(data)
        except:
            continue

    print("4")


# conn.shutdown(socket.SHUT_RDWR)
# conn.close()