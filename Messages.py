import RSA_Helper as RSA
import Signature_Helper as Sign
import AES_Helper as AES
from Crypto.Random import get_random_bytes
import time


class Message:

    def __init__(self):
        self.msgtype = None
        self.sender = None
        self.time = None
        self.msg = None
        self.validity = None


    def process_message(self, data, aes_key, sign_keys):
        """
        Process the message, and extract the useful information, if the message is valid.

        :param data: The message
        :param aes_key: Key to CBC
        :param sign_keys: Dictionary with the sender - key pairs
        :return: None - the object is filled
        """
        msgtype = data[0:3]

        if msgtype == "DAT".encode('utf-8'):
            iv = data[3:19]
            ciphertext = data[19:-512]
            plaintext = AES.decrypt(aes_key, ciphertext, iv)
            sign = data[-512:]
            timestamp = plaintext[0:5]
            sender = plaintext[5:10]
            msg = plaintext[10:]
            msg = msg.strip(b' ')
            sign_key = self.get_sign_key(sender, sign_keys)
            self.validity = Sign.verify_signature(data[:-512], sign_key.publickey(), sign)
        elif msgtype == "INI".encode('utf-8'):
            timestamp = data[3:8]
            sender = data[8:13]
            msg = data[13:-512]
            sign = data[-512:]
            sign_key = self.get_sign_key(sender, sign_keys)
            self.validity = Sign.verify_signature(data[:-512], sign_key.publickey(), sign)
        elif msgtype == "KEY".encode('utf-8'):
            ciphertext = data[3:-512]
            rsa_key = RSA.import_key("keypair.pem")
            plaintext = RSA.decrypt(rsa_key, ciphertext)
            timestamp = plaintext[0:5]
            sender = plaintext[5:10]
            msg = plaintext[10:]
            sign = data[-512:]
            sign_key = self.get_sign_key(sender, sign_keys)
            self.validity = Sign.verify_signature(data[:-512], sign_key.publickey(), sign)
        elif msgtype == "END".encode('utf-8'):
            iv = data[3:19]
            ciphertext = data[19:-512]
            plaintext = AES.decrypt(aes_key, ciphertext, iv)
            sign = data[-512:]
            timestamp = plaintext[0:5]
            sender = plaintext[5:10]
            sign_key = self.get_sign_key(sender, sign_keys)
            self.validity = Sign.verify_signature(data[:-512], sign_key.publickey(), sign)

        if self.validity == True:
            self.msgtype = msgtype.decode('utf-8')
            self.sender = sender.decode('utf-8')
            self.time = int.from_bytes(timestamp, 'big')
            self.msg = msg.decode('utf-8')

        return None

    def get_sign_key(self, sender, sign_keys):
        """
        Get the sender's signing key.

        :param sender: Message source
        :param sign_keys: Dictionary with the sender - key pairs
        :return: Sender's public sign key
        """
        try:
            sign_key = RSA.import_key(sign_keys[sender.decode('utf-8')])
        except KeyError:
            sign_key = RSA.import_key(sign_keys["dummy"])

        return sign_key




def create_DAT_message(msg, aes_key, sign_key, sender):
    """
    Create DAT type message. This type of message is for transmitting the chat messages.

    :param msg: string - Message to send
    :param aes_key: Key to CBC
    :param sign_key: Key to sign with
    :param sender: string - Source of the message
    :return: The framed message
    """
    msgtype = "DAT".encode('utf-8')
    timestamp = int(time.time()).to_bytes(5, 'big')
    sender = sender.encode('utf-8')
    msg = msg.encode('utf-8')

    rand = get_random_bytes(1)
    rand = int.from_bytes(rand, 'big')
    filler = (' '*rand).encode('utf-8')
    msg = msg + filler

    plaintext = timestamp + sender + msg
    iv, ciphertext = AES.encrypt(aes_key, plaintext)
    data = msgtype + iv + ciphertext
    sign = Sign.generate_signature(data, sign_key)
    data = data + sign

    return data


def create_INI_message(pub_key, sign_key, sender):
    """
    Create INI type message. This type of message is for initialize the connection.

    :param pub_key: The public key of the source
    :param sign_key: Key to sign with
    :param sender: string - Source of the message
    :return: The framed message
    """
    msgtype = "INI".encode('utf-8')
    timestamp = int(time.time()).to_bytes(5, 'big')
    sender = sender.encode('utf-8')
    pubkey = pub_key.exportKey(format='PEM').decode('ASCII').encode('utf-8')

    plaintext = msgtype + timestamp + sender + pubkey
    sign = Sign.generate_signature(plaintext, sign_key)
    data = plaintext + sign

    return data


def create_KEY_message(aes_key, pub_key, sign_key, sender):
    """
    Create KEY type message. This type of message is for transporting AES key.

    :param aes_key: Key to CBC
    :param pub_key: The public key of the destination
    :param sign_key: Key to sign with
    :param sender: string - Source of the message
    :return: The framed message
    """
    msgtype = "KEY".encode('utf-8')
    timestamp = int(time.time()).to_bytes(5, 'big')
    sender = sender.encode('utf-8')

    plaintext = timestamp + sender + aes_key
    ciphertext = RSA.encrypt(pub_key, plaintext)
    ciphertext = msgtype + ciphertext
    sign = Sign.generate_signature(ciphertext, sign_key)
    data = ciphertext + sign

    return data


def create_END_message(aes_key, sign_key, sender):
    """
    Create END type message. This type of message is for terminating connection.

    :param aes_key: Key to CBC
    :param sign_key: Key to sign with
    :param sender: string - Source of the message
    :return: The framed message
    """
    msgtype = "END".encode('utf-8')
    timestamp = int(time.time()).to_bytes(5, 'big')
    sender = sender.encode('utf-8')

    plaintext = timestamp + sender
    iv, ciphertext = AES.encrypt(aes_key, plaintext)
    data = msgtype + iv + ciphertext
    sign = Sign.generate_signature(data, sign_key)
    data = data + sign

    return data