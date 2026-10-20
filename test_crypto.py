# test_crypto.py

import crypto_utils

# Test RSA encryption/decryption
priv, pub = crypto_utils.generate_rsa_keypair(bits=1024)
message = b"Hello, RSA!"
ciphertext = crypto_utils.rsa_encrypt(pub, message)
decrypted = crypto_utils.rsa_decrypt(priv, ciphertext)
assert decrypted == message
print("RSA OK:", decrypted)

# Test AES encryption/decryption
key = crypto_utils.generate_aes_key()
secret = b"Secret AES message"
encrypted = crypto_utils.aes_encrypt(key, secret)
decrypted = crypto_utils.aes_decrypt(key, encrypted)
assert decrypted == secret
print("AES OK:", decrypted)
