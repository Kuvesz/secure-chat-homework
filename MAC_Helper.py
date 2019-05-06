from Crypto.Hash import SHA256, HMAC

def generate_MAC(msg, key):
    """
    Generate MAC

    :param msg: Message to compute MAC to
    :param key: MAC-key to compute MAC to
    :return: MAC
    """
    MAC = HMAC.new(key, digestmod=SHA256)
    MAC.update(msg)
    mac = MAC.digest()

    return mac


def verify_MAC(msg, mackey, mac):
    """
    Verify the MAC

    :param msg: Message to verify MAC to
    :param mackey: MAC-key
    :param signature: MAC to verify
    :return: bool - The result of the verification
    """
    MAC = HMAC.new(mackey, digestmod=SHA256)
    MAC.update(msg)
    comp_mac = MAC.digest()
    if mac == comp_mac:
        return True
    else:
        return False
