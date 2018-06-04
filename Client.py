#!/usr/bin/env python

import os
import socket
import colorama
from threading import Thread
from AESCipher import AESCipher
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import ast
import urllib.request
import shutil

def decryptRSA(encrypted):
	decryptor = PKCS1_OAEP.new(privateKey)
	decrypted = decryptor.decrypt(ast.literal_eval(str(encrypted)))
	return decrypted

def encryptRSA(decrypted):
	encryptor = PKCS1_OAEP.new(publicKey)
	encrypted = encryptor.encrypt(decrypted)
	return encrypted

def decryptAES(encrypted, key):
	decryptor = AESCipher(key)
	decrypted = decryptor.decrypt(encrypted)
	return decrypted

def encryptAES(decrypted, key):
	encryptor = AESCipher(key)
	encrypted = encryptor.encrypt(decrypted)
	return encrypted

def sendToServer(message):
	message = message.encode('utf-8')
	encMessage = encryptAES(message, key)
	s.send(encMessage)

def clear():
	if os.name == 'nt':
		_ = os.system('cls')
	else:
		_ = os.system('clear')

def listen():
	while True:
		try:
			inMessageEnc = s.recv(1024)
			inMessage = decryptAES(inMessageEnc, key).decode('utf-8')
		except:
			break
		print('\r\x1b[2K{}'.format(inMessage))
		print("{}> ".format(name), end="", flush=True)

print("CLIENT")

#if not os.path.exists('public.pem'):
#	print("Downloading public RSA key.")
#	urllib.request.urlretrieve("http://web.server/public.pem", "public.pem")

with open("public.pem", "r") as file:
	publicKeyString = file.read()
publicKey = RSA.import_key(publicKeyString)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
colorama.init()
erase = '\x1b[1A\x1b[2K'
name = input("Your username: ")

try:
	print("Connecting...\r", end="")
	#s.connect(("web.server",5006))
	s.connect(("127.0.0.1",5006))
	key = os.urandom(16)
	keyEnc = encryptRSA(key)
	s.send(keyEnc)
	print("Connected with AES.")
	initialResponseEnc = s.recv(1024)
	initialResponse = decryptAES(initialResponseEnc, key)
	if initialResponse == b'Who are you?':
		sendToServer(name)
		connectedEnc = s.recv(1024).decode('utf-8')
		connected = decryptAES(connectedEnc, key).decode('utf-8')
		print(connected)
	Thread(target=listen).start()
	while True:
		outMessage = input("{}> ".format(name))
		if outMessage == "exit" or outMessage == "quit":
			break
		outMessageCombo = "{}> {}".format(name, outMessage)
		print((erase * ((len(outMessageCombo) // shutil.get_terminal_size().columns) + 1)) + outMessageCombo)
		if outMessage == "cls" or outMessage == "clear":
			clear()
			continue
		sendToServer(outMessage)
except Exception as err:
	print("Error Connecting")
	print(err)
finally:
	sendToServer('I am out.')
	s.close()
	print("Closed Socket")