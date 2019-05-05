from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256

def generate_signature(msg, key):
    """
    Generate signature

    :param msg: Message to be signed
    :param key: RSA keypair to sign with
    :return: Signature
    """
    h = SHA256.new()
    h.update(msg)
    signer = PKCS1_PSS.new(key)
    signature = signer.sign(h)

    return signature

def verify_signature(msg, pubkey, signature):
    """
    Verify the signature

    :param msg: Signed message
    :param pubkey: RSA public key
    :param signature: Signature to verify
    :return: bool - The result of the verification
    """
    h = SHA256.new()
    h.update(msg)
    verifier = PKCS1_PSS.new(pubkey)

    if verifier.verify(h, signature):
        return True
    else:
        return False