'''
    author : zerobits01
    created: 28-Jan-2020
    purpose: symmetric encryption with xor
'''

import string
import random

key = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase +\
                            string.digits) for _ in range(0, 1024))

print(key)

class XOREnc:
    def __init__(self, key):
        self.key = key

    def encrypt(self, message):
        return ''.join([
            chr(ord(c1) ^ ord(c2))
                for (c1, c2) in zip(message, self.key)
        ])

    def decrypt(self,encrypted):
        return self.encrypt(encrypted)

message = 'hello'
enc = XOREnc(key)

gebrash = enc.encrypt(message)
print(gebrash)
print(enc.decrypt(gebrash))