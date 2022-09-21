from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
import binascii

#  step 0: generate RSA keys
PR = RSA.generate(1024)
PU = PR.publickey()
delimiter = b',,,'  # delimiter allowing us to read each individual key/message content

with open("keys.pem", "wb") as f:  # writing PU and PR to file in binary mode
    f.write(PU.exportKey('PEM'))
    f.write(delimiter)
    f.write(PR.exportKey('PEM'))
    f.write(delimiter)
    f.close()

with open("keys.pem", "rb") as file:  # reading keys file and splitting them into a list that we can index through
    key_split = file.read().split(delimiter)


def rsa_encrypt(plain_text):  # defining encryption method that uses the receiver's PU to encrypt
    pub = RSA.importKey(key_split[0])
    rsa_cipher = PKCS1_OAEP.new(pub)
    cipher = rsa_cipher.encrypt(plain_text)
    return cipher


#  step 1: create AES key
aes_key = get_random_bytes(16)  # assigning aes_key to random byte length of 16
iv = get_random_bytes(16)  # assigning iv to same byte length as aes_key

#  step 2: encrypt AES key wit RSA public key
wrapped_aes = rsa_encrypt(aes_key)  # encrypting aes_key with our defined encryption function
with open("keys.pem", "ab") as f:  # appending iv to key file
    f.write(iv)  # 2
    f.write(delimiter)

#  step 3: Encrypt message using AES key
plain = input("please enter your message: ")    # given plain text
aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)  # defining the key, mode, iv for encryption
ciphertext = aes_cipher.encrypt(pad(plain.encode(), 16))  # encrypting plain text with padding

#  step 4: generate MAC
hmac = HMAC.new(wrapped_aes, digestmod=SHA256)  # using SHA256 and encrypted aes_key to create a mac
hmac.update(ciphertext)  # processing the encrypted plain text through the mac function

#  step 5: write steps 3, 2, and 4 to message file
with open("Transmitted_Data.txt", "wb") as f:  # writing in binary mode with delimiters
    f.write(ciphertext)
    f.write(delimiter)
    f.write(wrapped_aes)
    f.write(delimiter)
    f.write(hmac.digest())
    f.close()

print("message sent successfully!")
