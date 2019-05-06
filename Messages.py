import RSA_Helper as RSA
import Signature_Helper as Sign
import AES_Helper as AES
import time


def create_DAT_message(msg, key, sign_key, sender):
    """
    Create DAT type message. This type of message is for transmitting the chat messages.

    :param msg: string - Message to send
    :param key: Key to CBC
    :param sign_key: Key to sign with
    :param sender: string - Source of the message
    :return: The framed message
    """
    msgtype = "DAT".encode('utf-8')
    timestamp = int(time.time()).to_bytes(5, 'big')
    sender = sender.encode('utf-8')
    msg = msg.encode('utf-8')

    plaintext = timestamp + sender + msg
    iv, ciphertext = AES.encrypt(key, plaintext)
    data = msgtype + iv + ciphertext
    sign = Sign.generate_signature(data, sign_key)
    data = data + sign

    return data


def create_INI_message(pubkey, sign_key, sender):
    """
    Create INI type message. This type of message is for initialize the connection.

    :param pubkey: The public key of the source
    :param sign_key: Key to sign with
    :param sender: string - Source of the message
    :return: The framed message
    """
    msgtype = "INI".encode('utf-8')
    timestamp = int(time.time()).to_bytes(5, 'big')
    sender = sender.encode('utf-8')
    pubkey = pubkey.exportKey(format='PEM')

    plaintext = msgtype + timestamp + sender + pubkey
    sign = Sign.generate_signature(plaintext, sign_key)
    data = plaintext + sign

    return data
