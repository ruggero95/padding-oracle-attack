from paddingOracle import paddingOracle,BLOCK_SIZE_BYTES, interceptChyper
from Crypto.Random import get_random_bytes


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
                    if(paddingOracle(crackingBlocks)):
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
    