from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
import binascii

#  step 1: read message file
delimiter = b',,,'  # same delimiter as used in sender
with open("keys.pem", "rb") as file:  # reading keys file and splitting into list
    key_split = file.read().split(delimiter)
with open("Transmitted_Data.txt", "rb") as file:  # reading message and splitting into list
    message_split = file.read().split(delimiter)


cipher_text = message_split[0]  # defining needed variables according to their list index
mac = message_split[2]
wrapped_aes = message_split[1]
rsa_pr = key_split[1]
iv = key_split[2]

#  step 2: check MAC
hmac = HMAC.new(key=wrapped_aes, digestmod=SHA256)  # verifying the MAC that was included in the transmitted data
hmac.update(cipher_text)

try:  # giving two options for the possible outcomes of the MAC verification
  hmac.verify(mac)
  print("MAC is correct, message is authentic")
  verified = True
except ValueError:
  print("the message or the key is wrong")
  verified = False

#  step 3:  RSA decrypt the AES key
if verified:  # if MAC is correct, continue with the message decryption, if incorrect stop the process
    def rsa_decrypt(cipher_key, key):  # using generated PR key to decrypt the aes key
        priv = RSA.importKey(rsa_pr)
        rsa_cipher = PKCS1_OAEP.new(priv)
        dec_key = rsa_cipher.decrypt(cipher_key)
        return dec_key
    aes_key = rsa_decrypt(wrapped_aes, 'keys.pem')

#  step 4: AES decrypt the message
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)  # using the now decrypted aes key to decrypt the cipher text
    plain = unpad(cipher.decrypt(cipher_text), 16)
    print("message: ", plain.decode())
