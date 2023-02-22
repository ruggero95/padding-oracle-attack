from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import re


BLOCK_SIZE_BIT = 64
BLOCK_SIZE_BYTES = BLOCK_SIZE_BIT/8
#b bytes funtion
data = b'Unaligned'   # 9 bytes
key = get_random_bytes(BLOCK_SIZE_BYTES)
iv = get_random_bytes(BLOCK_SIZE_BYTES)

cipher1 = DES.new(key, DES.MODE_CBC, iv)


padded = pad(data, BLOCK_SIZE_BYTES)

def getCyhper(iv, key):
    return DES.new(key, DES.MODE_CBC, iv)


def encrypt(cipher, paddedMsg):
    return cipher.encrypt(paddedMsg)

def decrypt(cipher, ciphertext):
    return cipher.decrypt(ciphertext)

def paddingOracle(data, iv, key):
    try:
        dec = decrypt(getCyhper(iv, key), data)
        unpadded = (unpad(dec,BLOCK_SIZE_BYTES))
        return True
    except:
        return False


def paddingCheck(byteStep, bytes):
    toSearch = str(BLOCK_SIZE_BYTES - byteStep).zfill(2)
    reg = "[A-z0-9]*(?=("+toSearch+"){"+toSearch+"}$)"
    match = re.search(reg, bytearray(bytes).hex())
    if(match is not None):
        return toSearch
    return None


enc = iv + encrypt(getCyhper(iv, key), pad(data, BLOCK_SIZE_BYTES))
blocks = [enc[i:i + BLOCK_SIZE_BYTES] for i in range(0, len(enc), BLOCK_SIZE_BYTES)]
#print(b''.join(blocks))
# for each block
plaintext = ''
for i in reversed(range(0,len(blocks))):
    if(i>0):        
        originalBlock = blocks[i-1] #start from the second last
        changingBlock = bytearray(originalBlock)
        #copy that holdes the decrypted values calculated by xor with the fakeValues injected
        DvaluesHolder = bytearray(originalBlock)
        for b in reversed(range(len(changingBlock))):    #from the end of the byte block      
            padding = BLOCK_SIZE_BYTES - b
            
            if padding!=1:
                    #prepare other bytes to match the correct padding when is longer than 1
                    for prep in reversed(range((BLOCK_SIZE_BYTES-(padding-1)), BLOCK_SIZE_BYTES)):                        
                        print('prep'+str(DvaluesHolder[prep])+'^'+str(padding))
                        #dvalue should exist                                                
                        changingBlock[prep] = padding ^ DvaluesHolder[prep]
                        
            for fakeValue in range(0, 256):
                changingBlock[b] = fakeValue
                crackingBlocks = bytes(changingBlock) + blocks[i]                                                                                   
                if(paddingOracle(crackingBlocks, iv ,key)):
                    Dvalue = fakeValue ^ padding #C'8^P'12
                    DvaluesHolder[b] = Dvalue
                    plaintext += chr(Dvalue ^ originalBlock[b])
                    break
                #decrypt and padding check
            
print('plain')                
print((plaintext[::-1]))
    
#TODO
# change the old values to a value that can have 0x2 as padding-->  P'2[16] ^ I2[16] = 02 ^ trovatoprimaDvalue
#uguale anche a fakeValue precedente ^ padding ^ padding precedente