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
import configparser
import argparse

def parse_config():
	global privateKeyFile, port, max_users, debug, allow_encryption
	privateKeyFile_default = 'private.pem'
	port_default = 5006
	max_users_default = 2048
	debug_default = False
	config_file_default = 'server.ini'
	allow_encryption_default = True
	
	config = configparser.ConfigParser()
	config.read(config_file)
	section = "Server"
	try:
		config_server = config[section]
	except:
		privateKeyFile = privateKeyFile_default
		port = port_default
		max_users = max_users_default
		debug = debug_default
		allow_encryption = allow_encryption_default
		if config_file != config_file_default:
			print("\nSomething wrong with config file ({}).\n".format(config_file))
		return
	
	errorWith = []
	
	privateKeyFile = config_server.get('privatekeyfile', privateKeyFile_default)
	
	try:
		port = config_server.getint('port', port_default)
	except:
		errorWith.append('port')
		port = port_default
	
	try:
		max_users = config_server.getint('maxusers', max_users_default)
	except:
		errorWith.append('maxusers')
		max_users = max_users_default
	
	try:
		allow_encryption = config_server.getboolean('allowencryption', allow_encryption_default)
	except:
		errorWith.append('allowencryption')
		allow_encryption = allow_encryption_default
	
	try:
		debug = config_server.getboolean('debug', debug_default)
	except:
		errorWith.append('debug')
		debug = debug_default
	
	if errorWith: print('\nErrors with loading [{}] from config file.\n'.format(', '.join(errorWith)))

def parse_args():
	parser = argparse.ArgumentParser(description='Provides a dedicated server for Clients to connect to.\nAll settings here override the config file.')
	parser.add_argument('-p', '--port', type=int, help='Specify the port number to host on.', action='store')
	parser.add_argument('-m', '--maxusers', type=int, help='Specify the max number of users that can connect.', action='store')
	parser.add_argument('-pK', '--privatekey', help='Specify the private key to use.', action='store')
	parser.add_argument('-c', '--config', help='Specify the config file to use.', action='store')
	parser.add_argument('-dE', '--dontencrypt', help="Specify if clients shouldn't be able to use encryption when connecting.", action='store_true')
	parser.add_argument('-d', '--debug', help=argparse.SUPPRESS, action='store_true')
	args = parser.parse_args()
	global config_file, privateKeyFile, port, max_users, allow_encryption, debug
	if args.config:
		config_file = args.config
		parse_config()
	if args.privatekey:
		privateKeyFile = args.privatekey
	if args.maxusers:
		max_users = args.maxusers
	if args.port:
		port = args.port
	if args.dontencrypt:
		allow_encryption = not args.dontencrypt
	if args.debug:
		debug = args.debug

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
			if keys.get(eachID):
				eachConn.send(encryptAES(message, keys[eachID]))
			else:
				eachConn.send(message)

def hereList():
	return "Here exists {}.".format(', '.join(list(names.values())))

def getID():
	rand = random.randint(0, max_users - 1)
	while rand in list(names.keys()):
		rand = random.randint(0, max_users - 1)
	return rand

def talk(conn, addr):
	print("Opening connection with {}.".format(addr))
	
	try:
		rand = getID()
		ID = str(rand)
		connections[ID] = conn
		initialMessage = conn.recv(1024)
		try:
			key = decryptRSA(initialMessage)
			keys[ID] = key
			nameEnc = conn.recv(1024)
			name = decryptAES(nameEnc, key).decode('utf-8')
			if not allow_encryption:
				conn.send(encryptAES(b'Encryption is not allowed here.', key))
				return
		except ValueError as err:
			try:
				name = initialMessage.decode('utf-8')
			except Exception as err:
				print("Malformed input, kicking.")
				conn.send(b'Malformed input, kicking.')
				if debug:
					print(err)
				return
		except Exception as err:
			print("Malformed input, kicking.")
			conn.send(b'Malformed input, kicking.')
			if debug:
				print(err)
			return

		names[ID] = name
		
		print("They are {} with the ID of {}.".format(name, ID))
		if keys.get(ID):
			conn.send(encryptAES(hereList().encode('utf-8'), key))
		else:
			conn.send(hereList().encode('utf-8'))
		
		broadcast("{} has joined.".format(name).encode('utf-8'), ID)
		while True:
			try:
				if keys.get(ID):
					dataEnc = conn.recv(1024)
					data = decryptAES(dataEnc, key)
				else:
					data = conn.recv(1024)
			except Exception as err:
				print("Error Receiving")
				data = b'exit'
				if debug:
					print(err)
			if data == b'I am out.' or data == b'exit' or data == b'quit':
				break
			elif data == b'who':
				if keys.get(ID):
					conn.send(encryptAES(hereList().encode('utf-8'), key))
				else:
					conn.send(hereList().encode('utf-8'))
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
			if connections.get(ID):
				del connections[ID]
			if keys.get(ID):
				del keys[ID]
			if names.get(ID):
				del names[ID]
			print("Closed connection with {}.".format(addr))
			print("They were {} with the ID of {}.".format(name, ID))
			message = "{} has left.".format(name).encode('utf-8')
			broadcast(message, ID)
		except Exception as err:
			print("Some kind of error in cleaning up that connection. They probably didn't have a name or key.")
			if debug:
				print(err)
		conn.close()

def listening():
	while True:
		conn, addr = s.accept()
		Thread(target=talk, args=(conn, addr)).start()

if __name__ == "__main__":
	print("SERVER")
	
	config_file = "server.ini"
	parse_config()
	parse_args()
	
	if debug:
		print("DEBUG")
		#exit()
	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(("0.0.0.0",port))
	s.listen(5)
	
	with open(privateKeyFile, "r") as file:
		privateKeyString = file.read()
	privateKey = RSA.import_key(privateKeyString)
	
	connections = {}
	names = {}
	keys = {}
	
	thread = Thread(target=listening)
	thread.daemon = True
	thread.start()
	
	try:
		while True:
			time.sleep(100)
	except KeyboardInterrupt:
		s.close()
		print("Closing Server")
		exit()