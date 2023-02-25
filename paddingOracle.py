from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes


BLOCK_SIZE_BIT = 64
BLOCK_SIZE_BYTES = int(BLOCK_SIZE_BIT/8)
KEY = get_random_bytes(BLOCK_SIZE_BYTES)
IV = get_random_bytes(BLOCK_SIZE_BYTES)

def getCyhper():
  
    return DES.new(KEY, DES.MODE_CBC, IV)
    

def encrypt(cipher, paddedMsg):
    return cipher.encrypt(paddedMsg)

def decrypt(cipher, ciphertext):
    return cipher.decrypt(ciphertext)

def paddingOracle(data):
    try:
        dec = decrypt(getCyhper(), data)
        up = (unpad(dec, BLOCK_SIZE_BYTES))
        return True
    except:
        return False
    
def interceptChyper(msg: str) -> bytes:
    return  IV + encrypt(getCyhper(), pad(msg, BLOCK_SIZE_BYTES))
