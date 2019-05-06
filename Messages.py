import RSA_Helper as RSA
import Signature_Helper as Sign
import AES_Helper as AES
import time


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
    pubkey = pub_key.exportKey(format='PEM')

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