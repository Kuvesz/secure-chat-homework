import threading
import Messages

class input_reader (threading.Thread):

    def __init__(self, active):
        threading.Thread.__init__(self)
        self.input_list = []
        self.active = active

    def run(self):
        while self.active:
            self.input_list.append(input(""))
            try:
                self.input_list.remove('')
            except:
                pass
class data_reader (threading.Thread):

    def __init__(self, socket, active):
        threading.Thread.__init__(self)
        self.data_list = []
        self.socket = socket
        self.socket.settimeout(1)
        self.end = False
        self.active = active

    def run(self):
        while self.active:
            try:
                data = self.socket.recv(4096)
                print("recv")
                if not data:
                    self.end = True
                self.data_list.append(data)
            except:
                pass