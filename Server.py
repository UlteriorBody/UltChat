#!/usr/bin/env python

import socket
import time
import random
import os
from threading import Thread
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import ast
from AESCipher import AESCipher

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

def broadcast(message, senderID):
	for eachID, eachConn in connections.items():
		if eachID != senderID:
			eachConn.send(encryptAES(message, keys[eachID]))

def hereList():
	return "Here exists {}.".format(', '.join(list(names.values())))

def getID():
	rand = random.randint(0,2047)
	while rand in list(names.keys()):
		rand = random.randint(0,2047)
	return rand

def talk(conn, addr):
	print("Opening connection with {}.".format(addr))
	try:
		rand = getID()
		ID = str(rand)
		connections[ID] = conn
		keyEnc = conn.recv(1024)
		try:
			key = decryptRSA(keyEnc)
		except ValueError as err:
			print("Malformed input, kicking.")
			return
		keys[ID] = key
		conn.send(encryptAES(b'Who are you?', key))
		nameEnc = conn.recv(1024)
		name = decryptAES(nameEnc, key).decode('utf-8')
		names[ID] = name
		print("They are {} with the ID of {}.".format(name, ID))
		conn.send(encryptAES(hereList().encode('utf-8'), key))
		broadcast("{} has joined.".format(name).encode('utf-8'), ID)
		while True:
			try:
				dataEnc = conn.recv(1024)
				data = decryptAES(dataEnc, key)
			except KeyboardInterrupt as err:
				break
			except Exception as err:
				print("Error Receiving")
				data = b'exit'
			if data == b'I am out.' or data == b'exit' or data == b'quit':
				break
			elif data == b'who':
				conn.send(encryptAES(hereList().encode('utf-8'), key))
			elif data:
				message = "{}> {}".format(name, data.decode('utf-8'))
				message = message.encode('utf-8')
				broadcast(message, ID)
			else:
				message = "{}> {}".format(name, data.decode('utf-8'))
				message = message.encode('utf-8')
				broadcast(message, ID)
	finally:
		try:
			del connections[ID]
			del keys[ID]
			del names[ID]
			print("Closed connection with {}.".format(addr))
			print("They were {} with the ID of {}.".format(name, ID))
			message = "{} has left.".format(name).encode('utf-8')
			broadcast(message, ID)
		except:
			print("Some kind of error in cleaning up that connection. They probably didn't have a name or key.")
		conn.close()

print("SERVER")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0",5006))
s.listen(5)

with open("private.pem", "r") as file:
	privateKeyString = file.read()
privateKey = RSA.import_key(privateKeyString)

connections = {}
names = {}
keys = {}

while True:
	conn, addr = s.accept()
	Thread(target=talk, args=(conn, addr)).start()