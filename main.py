from Crypto.Cipher import AES
import hashlib
import os
from Crypto.Util import Counter
from Crypto import Random

iv = os.urandom(16)
myKey = "SarahAlharbi"
key = hashlib.sha256(myKey.encode('utf-8')).digest()

#ECB
def encryptECB():
  cipher = AES.new(key, AES.MODE_ECB)
  
  with open("snail.bmp", "rb") as f:
    block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  cipherBlock = block[0:64] + cipher.encrypt(blockTrimmed) + block[pad:]  
  
  with open("ECB_snail_E.bmp", "wb") as f:
    block = f.write(cipherBlock)
  return block

def decryptECB():
  cipher = AES.new(key, AES.MODE_ECB)
  
  with open("ECB_snail_E.bmp", "rb") as f:
    block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  plain = cipher.decrypt(blockTrimmed)
  plain = block[0:64] + cipher.decrypt(blockTrimmed) + block[pad:] 
  
  with open("ECB_snail_D.bmp", "wb") as f:
    block = f.write(plain)
#CBC
def encryptCBC():
  cipher = AES.new(key, AES.MODE_CBC, iv)
  
  with open("snail.bmp", "rb") as f:
     block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  cipherBlock = block[0:64] + cipher.encrypt(blockTrimmed) + block[pad:] 
  
  with open("CBC_snail_E.bmp", "wb") as f:
     f.write(cipherBlock)
    
def decryptCBC():
  cipher = AES.new(key, AES.MODE_CBC, iv)
  
  with open("CBC_snail_E.bmp", "rb") as f:
    block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  plain = cipher.decrypt(blockTrimmed)
  plain = block[0:64] + plain + block[pad:]
  
  with open("CBC_snail_D.bmp", "wb") as f:
    block = f.write(plain)
#OFB
def encryptOFB():
  cipher = AES.new(key, AES.MODE_OFB, iv)
  
  with open("snail.bmp", "rb") as f:
     block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  cipherBlock = block[0:64] + cipher.encrypt(blockTrimmed) + block[pad:] 
  
  with open("OFB_snail_E.bmp", "wb") as f:
     f.write(cipherBlock)

def decryptOFB():
  cipher = AES.new(key, AES.MODE_OFB, iv)
  
  with open("OFB_snail_E.bmp", "rb") as f:
    block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  plain = cipher.decrypt(blockTrimmed)
  plain = block[0:64] + plain + block[pad:]
  
  with open("OFB_snail_D.bmp", "wb") as f:
    block = f.write(plain)
#CFB
def encryptCFB():
  cipher = AES.new(key, AES.MODE_CFB, iv)
  
  with open("snail.bmp", "rb") as f:
    block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  cipherBlock = block[0:64] + cipher.encrypt(blockTrimmed) + block[pad:]   
  
  with open("CFB_snail_E.bmp", "wb") as f:
    block = f.write(cipherBlock)
  return block

def decryptCFB():
  cipher = AES.new(key, AES.MODE_CFB, iv)
  
  with open("CFB_snail_E.bmp", "rb") as f:
    block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  plain = cipher.decrypt(blockTrimmed)
  plain = block[0:64] + plain + block[pad:] 
  
  with open("CFB_snail_D.bmp", "wb") as f:
    block = f.write(plain)

#CTR
nonce= Random.get_random_bytes(8)
ctr = Counter.new(64, nonce)

def encryptCTR():
  cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
  
  with open("snail.bmp", "rb") as f:
     block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  cipherBlock = block[0:64] + cipher.encrypt(blockTrimmed) + block[pad:] 
  
  with open("CTR_snail_E.bmp", "wb") as f:
     f.write(cipherBlock)

def decryptCTR():
  ctr = Counter.new(64, nonce)
  cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
  
  with open("CTR_snail_E.bmp", "rb") as f:
    block = f.read()
  pad = len(block)%16 * -1
  blockTrimmed = block[64:pad]
  plain = cipher.decrypt(blockTrimmed)
  plain = block[0:64] + plain + block[pad:]
  
  with open("CTR_snail_D.bmp", "wb") as f:
    block = f.write(plain)

#MAIN
encryptECB()
decryptECB()
encryptCBC()
decryptCBC()
encryptOFB()
decryptOFB()
encryptCFB()
decryptCFB()
encryptCTR()
decryptCTR()
print('WE HAVE DONE!')