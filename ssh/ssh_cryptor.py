from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from io import BytesIO

import base64
import zlib

def generate(pri_name='pri', pub_name='pub'):
    newkey = RSA.generate(2048)
    privatekey = newkey.exportKey()
    publickey = newkey.publickey().exportKey()
    
    with open(f'key.{pri_name}', 'wb') as b:
        b.write(privatekey)
        
    with open(f'key.{pub_name}', 'wb') as c:
        c.write(publickey)
        
        
def get_rsa_cipher(keytype):
    with open(f'key.{keytype}') as d:
        key = d.read()
    rsakey = RSA.importKey(key)
    return (PKCS1_OAEP.new(rsakey), rsakey.size_in_bytes())

def encrypt(plaintext, type='pub'):
    compressed_text = zlib.compress(plaintext)
    
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_text)
    
    cipher_rsa, _ = get_rsa_cipher(f'{type}')
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    msg_payload = encrypted_session_key + cipher_aes.nonce + tag + ciphertext
    encrypted = base64.encodebytes(msg_payload)
    return(encrypted)

def decrypt(encrypt, type='pri'):
    encrypted_bytes = BytesIO(base64.decodebytes(encrypt))
    cipher_rsa, keysize_in_bytes = get_rsa_cipher(f'{type}')
    
    encrypt_session_key = encrypted_bytes.read(keysize_in_bytes)
    nonce = encrypted_bytes.read(16)
    tag = encrypted_bytes.read(16)
    ciphertext = encrypted_bytes.read()
    
    session_key = cipher_rsa.decrypt(encrypt_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    plaintext = zlib.decompress(decrypted)
    return plaintext

if __name__ == '__main__':
    generate()
    plaintext = b'hello'
    print(decrypt(encrypt(plaintext)))
    
    