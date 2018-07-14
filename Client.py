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
import configparser
import argparse

def parse_config():
	global publicKeyFile, port, do_encrypt, server_address, key_length, debug
	publicKeyFile_default = 'public.pem'
	port_default = 5006
	do_encrypt_default = False
	server_address_default = '127.0.0.1'
	key_length_default = 16
	debug_default = False
	config_file_default = 'client.ini'
	
	config = configparser.ConfigParser()
	config.read(config_file)
	section = "Client"
	try:
		config_client = config[section]
	except:
		publicKeyFile = publicKeyFile_default
		port = port_default
		do_encrypt = do_encrypt_default
		server_address = server_address_default
		key_length = key_length_default
		debug = debug_default
		if config_file != config_file_default:
			print("\nSomething wrong with config file ({}).\n".format(config_file))
		return
	
	errorWith = []
	
	publicKeyFile = config_client.get('publickeyfile', publicKeyFile_default)
	
	try:
		port = config_client.getint('port', port_default)
	except:
		errorWith.append('port')
		port = port_default
	
	try:
		do_encrypt = config_client.getboolean('encrypt', do_encrypt_default)
	except:
		errorWith.append('encrypt')
		do_encrypt = do_encrypt_default
	
	server_address = config_client.get('serveraddress', server_address_default)
		
	valid_key_lengths = [16, 24, 32]
	try:
		key_length = config_client.getint('keylength', key_length_default)
	except:
		errorWith.append('keylength')
		key_length = key_length_default
	if not key_length in valid_key_lengths:
		key_length = key_length_default
		errorWith.append('keylength')
	
	try:
		debug = config_client.getboolean('debug', debug_default)
	except:
		errorWith.append('debug')
		debug = debug_default
	
	print('Errors with loading [{}] from config file.'.format(', '.join(errorWith)) * bool(len(errorWith)))

def parse_args():
	parser = argparse.ArgumentParser(description='Connect to a dedicated server.\nAll settings here override the config file.')
	parser.add_argument('-p', '--port', type=int, help='Specify the port number to connect to.', action='store')
	parser.add_argument('-sA', '--serveraddress', type=str, help='Specify the server address to connect to.', action='store')
	parser.add_argument('-kL', '--keylength', type=int, help='Specify the AES key length.', action='store')
	parser.add_argument('-nE', '--noencryption', help='Specify this to disable encryption.', action='store_true')
	parser.add_argument('-pK', '--publickey', type=str, help='Specify the public key to use when connecting to the server.', action='store')
	parser.add_argument('-c', '--config', type=str, help='Specify the config file to use.', action='store')
	parser.add_argument('-d', '--debug', help=argparse.SUPPRESS, action='store_true')
	args = parser.parse_args()
	global publicKeyFile, port, do_encrypt, debug, server_address, key_length, config_file
	if args.config:
		config_file = args.config
		parse_config()
	if args.publickey:
		publicKeyFile = args.publickey
	if args.noencryption:
		do_encrypt = not args.noencryption
	if args.port:
		port = args.port
	if args.serveraddress:
		server_address = args.serveraddress
	if args.keylength:
		key_length = args.keylength
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

def sendToServer(message):
	message = message.encode('utf-8')
	if do_encrypt:
		encMessage = encryptAES(message, key)
		s.send(encMessage)
	else:
		s.send(message)

def clear():
	if os.name == 'nt':
		_ = os.system('cls')
	else:
		_ = os.system('clear')

def numberOfLines(message):
	return (len(message) // shutil.get_terminal_size().columns) + 1

def listen():
	while True:
		try:
			if do_encrypt:
				inMessageEnc = s.recv(1024)
				inMessage = decryptAES(inMessageEnc, key).decode('utf-8')
				if inMessage == b'Encryption is not allowed here.':
					print("Encryption is not allowed here, sorry.")
					raise
			else:
				inMessage = s.recv(1024).decode('utf-8')
		except Exception as err:
			if debug:
				print(err)
			s.close()
			exit()
		print('\r\x1b[2K{}'.format(inMessage))
		print("{}> ".format(name), end="", flush=True)

if __name__ == "__main__":
	print("CLIENT")
	
	config_file = 'client.ini'
	parse_config()
	parse_args()
	
	if debug:
		print("DEBUG")

	#if not os.path.exists(publicKeyFile):
	#	print("Downloading public RSA key.")
	#	urllib.request.urlretrieve("http://{}/{}".format(server_address, publicKeyFile), publicKeyFile)

	if do_encrypt:
		with open(publicKeyFile, "r") as file:
			publicKeyString = file.read()
		publicKey = RSA.import_key(publicKeyString)

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	colorama.init()
	erase = '\x1b[1A\x1b[2K'
	name = input("Your username: ")

	try:
		print("Connecting...\r", end="")
		s.connect((server_address, port))
		if do_encrypt:
			key = os.urandom(key_length)
			keyEnc = encryptRSA(key)
			s.send(keyEnc)
			print("Connected with AES.")
		
		sendToServer(name)
		if do_encrypt:
			connectedEnc = s.recv(1024).decode('utf-8')
			connected = decryptAES(connectedEnc, key).decode('utf-8')
		else:
			connected = s.recv(1024).decode('utf-8')
		print(connected)
		
		Thread(target=listen).start()
		while True:
			try:
				outMessage = input("{}> ".format(name))
			except KeyboardInterrupt:
				print("\nOkay, bye.")
				s.close()
				exit()
			if outMessage == "exit" or outMessage == "quit":
				break
			outMessageCombo = "{}> {}".format(name, outMessage)
			print((erase * numberOfLines(outMessageCombo)) + outMessageCombo)
			if outMessage == "cls" or outMessage == "clear":
				clear()
				continue
			sendToServer(outMessage)
	except Exception as err:
		print("Cannot Connect To Server")
		print("Check Configuration and Try Again")
		if debug:
			print(err)
	finally:
		try:
			sendToServer('I am out.')
		except Exception as err:
			if debug:
				print(err)
		s.close()
		print("Connection Closed With Server")