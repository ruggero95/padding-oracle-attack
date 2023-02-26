from time import sleep
from paddingOracle import paddingOracle,BLOCK_SIZE_BYTES, interceptChyper
import sys
import re
def printAnimation(text):
    sleep(0.03)
    sys.stdout.write("\r"+text)
    sys.stdout.flush()

def attack(msg: str):
    encrypted = interceptChyper(msg)
    #split encrypted bytes in blocks
    blocks = [encrypted[i:i + BLOCK_SIZE_BYTES] for i in range(0, len(encrypted), BLOCK_SIZE_BYTES)]
    plaintext = ''
    # for each block    
    for i in reversed(range(0,len(blocks))):    
        if(i>0):  #avoid processing last block
            originalBlock = blocks[i-1] #start from the second last
            changingBlock = bytearray(originalBlock)
            #copy that holdes the decrypted values calculated by xor with the fakeValues injected
            DvaluesHolder = bytearray(originalBlock)
            #from the end of the byte block
            for b in reversed(range(len(changingBlock))):          
                padding = BLOCK_SIZE_BYTES - b
                #if padding is 1 we are at the bottom of the string no need to change previous bytes to padding
                if padding!=1:
                    #prepare other bytes to match the correct padding when is longer than 1
                    for prep in reversed(range((BLOCK_SIZE_BYTES-(padding-1)), BLOCK_SIZE_BYTES)):                                                                                                 
                        changingBlock[prep] = padding ^ DvaluesHolder[prep]
                #strart injecting fake values to obtain a valid padding
                for fakeValue in range(0, 256):
                    changingBlock[b] = fakeValue
                    #rejoin fackedBlock with previus original blocks
                    fackedBlocks = bytes(changingBlock) + blocks[i]                                                                                   
                    if(paddingOracle(fackedBlocks)):
                        Dvalue = fakeValue ^ padding
                        #saving decrypted value for later use searching other paddings
                        DvaluesHolder[b] = Dvalue
                        plaintext += chr(Dvalue ^ originalBlock[b])
                        printAnimation(plaintext[::-1])
                        break
    print(' ')
    return  plaintext[::-1]

if __name__ == "__main__":
    msg =[b'test msg',b'test on longer message',b'test on longer message, also a lot longer message than previous']   # 9 bytes
    argv = ''.join(sys.argv)
    if(re.search('demo',argv) is None):
        inp = input('insert the message to attack:\r\n')
        msg = [bytes(inp, "utf-8")]
    for i in range(len(msg)):    
        attack(msg[i])

    