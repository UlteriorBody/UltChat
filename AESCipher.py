#!/usr/bin/env python

import os
import base64
from Cryptodome.Cipher import AES


class AESCipher(object):
	def __init__(self, key):
		self.bs = AES.block_size
		self.cipherMachine = AES.new(key, AES.MODE_ECB)
	
	def encrypt(self, raw):
		raw = self.pad(raw)
		encrypted = self.cipherMachine.encrypt(raw)
		encoded = base64.b64encode(encrypted)
		return encoded
	
	def decrypt(self, raw):
		decoded = base64.b64decode(raw)
		decrypted = self.cipherMachine.decrypt(decoded)
		decrypted = self.unpad(decrypted)
		return decrypted
	
	def pad(self, s):
		length = self.bs - (len(s) % self.bs)
		s += bytes([length])*length
		return s
	
	def unpad(self, s):
		return s[:-s[-1]]

if __name__ == '__main__':
	key = os.urandom(16)
	cipher = AESCipher(key)
	
	plaintext = b"test"
	encrypted = cipher.encrypt(plaintext)
	print('Encrypted: {}'.format(encrypted))
	
	decrypted = cipher.decrypt(encrypted)
	print('Decrypted: {}'.format(decrypted))
	
	assert decrypted == plaintext