from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_keypair():
    """
    Generate 4096 bit long RSA keypair

    :return: Keypair
    """
    key = RSA.generate(4096)

    return key


def export_keypair(file_name, key):
    """
    Export the RSA keypair into a file

    :param file_name: File name to export
    :param key: Key to eyport
    :return: None
    """
    ofile = open(file_name, 'w')
    ofile.write(key.exportKey(format='PEM').decode('ASCII'))
    ofile.close()


def import_keypair(file_name):
    """
    Import the RSA keypair from a file

    :param file_name: File name from import
    :return: Keypair
    """
    kfile = open(file_name, 'r')
    keystr = kfile.read()
    kfile.close()
    key = RSA.import_key(keystr)

    return key


def encrypt(pubkey, plaintext):
    """
    Simple RSA encrypt function

    :param pubkey: Public key to encrypt with
    :param plaintext: Bytes to encrypt
    :return: Encrypted bytes
    """
    cipher = PKCS1_OAEP.new(pubkey)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext


def decrypt(key, ciphertext):
    """
    Simple RSA decrypt function

    :param privkey: Private key to decrypt with
    :param ciphertext: Bytes to decrypt
    :return: Decrypted bytes
    """
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext