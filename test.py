from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import re

BYTES_BLOCK = 8
BIT_block = 64
#b bytes funtion
data = b'Unaligned'   # 9 bytes
key = get_random_bytes(BYTES_BLOCK)
iv = get_random_bytes(BYTES_BLOCK)

cipher1 = DES.new(key, DES.MODE_CBC, iv)


padded = pad(data, BYTES_BLOCK)
print(padded)
print(len(padded))


def getCyhper(iv, key):
    return DES.new(key, DES.MODE_CBC, iv)


def encrypt(cipher, paddedMsg):
    return cipher.encrypt(paddedMsg)

def decrypt(cipher, ciphertext):
    return cipher.decrypt(ciphertext)

def paddingOracle(data, iv, key):
    try:
        dec = decrypt(getCyhper(iv, key), data)
        print(dec)
        up = (unpad(dec,BYTES_BLOCK))
        return True
    except:
        return False

'''
enc = encrypt(getCyhper(iv, key), pad(data, BYTES_BLOCK))
dec = decrypt(getCyhper(iv, key), enc)

print('---')
print(enc)
print(dec)

blocks = [enc[i:i + BYTES_BLOCK] for i in range(0, len(enc), BYTES_BLOCK)]
    

print(blocks)
print(paddingOracle(dec))

print(paddingOracle(padded))
print(paddingOracle(data))
print(paddingOracle('lskdjfdlkj'))
'''

'''
 b'\xde\xad\xbe\xef'.hex()
'deadbeef'
and reverse:

bytes.fromhex('deadbeef')
b'\xde\xad\xbe\xef'
'''

def paddingCheck(byteStep, bytes):
    toSearch = str(BYTES_BLOCK - byteStep).zfill(2)
    reg = "[A-z0-9]*(?=("+toSearch+"){"+toSearch+"}$)"
    match = re.search(reg, bytearray(bytes).hex())
    if(match is not None):
        return toSearch
    return None
    '''    
    print(bytearray(bytes).hex())
    for s in reversed(range(0,toSearch)):
        print('********')
        print(bytes[s])
        print(toSearch)
        if bytes[s]!= toSearch:
            return False
    return True
    '''

enc = iv + encrypt(getCyhper(iv, key), pad(data, BYTES_BLOCK))
print(enc)
blocks = [enc[i:i + BYTES_BLOCK] for i in range(0, len(enc), BYTES_BLOCK)]
print(blocks)
#print(b''.join(blocks))
# for each block
plaintext = ''
for i in reversed(range(0,len(blocks))):
    if(i>0):        
        originalBlock = blocks[i-1] #start from the second last
        changingBlock = bytearray(originalBlock)
        DvaluesHolder = bytearray(originalBlock)
        print(changingBlock)
        for b in reversed(range(len(changingBlock))):    #from the end of the byte block      
            padding = BYTES_BLOCK - b
            print(padding)
            print(b)
            if padding!=1:
                    #prepare other bytes to match the correct padding when is longer than 1
                    for prep in reversed(range((BYTES_BLOCK-(padding-1)), BYTES_BLOCK)):                        
                        print('prep'+str(DvaluesHolder[prep])+'^'+str(padding))
                        #dvalue should exist                                                
                        changingBlock[prep] = padding ^ DvaluesHolder[prep]
                        
            for fakeValue in range(0, 256):
                changingBlock[b] = fakeValue
                crackingBlocks = bytes(changingBlock) + blocks[i]                                                                                   
                if(paddingOracle(crackingBlocks, iv ,key)):
                    print('-------')
                    print('operation:'+str(padding)+ "^" + str(fakeValue))
                    Dvalue = fakeValue ^ padding #C'8^P'12
                    DvaluesHolder[b] = Dvalue
                    plaintext += chr(Dvalue ^ originalBlock[b])
                    break
                #decrypt and padding check
            
print('plain')                
print(plaintext)
    
#TODO
# change the old values to a value that can have 0x2 as padding-->  P'2[16] ^ I2[16] = 02 ^ trovatoprimaDvalue
#uguale anche a fakeValue precedente ^ padding ^ padding precedente