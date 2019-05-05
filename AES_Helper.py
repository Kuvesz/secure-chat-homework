from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes


def encrypt(key, plaintext):
    """
    Simple AES encryption

    :param key: Key to encrypt with
    :param plaintext: Bytes to encrypt
    :return:
    """
    plaintext = Padding.pad(plaintext, AES.block_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)

    return iv, ciphertext


def decrypt(key, ciphertext, iv):
    """
    Simple AES decrytion

    :param key: Key to decrypt with
    :param ciphertext: Bytes to decrypt
    :param iv: IV for CBC init
    :return:
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = Padding.unpad(plaintext, AES.block_size)

    return plaintext
