#!/usr/bin/env python

"""
IMPORTANT NOTE:
This code is written using Python 2.7.5 and will not correctly run on Python 3. 
If you are running into issues check the Python version of your machine. This 
code can be converted to Python 3 by changing the raw_inputs to input.
"""
import os
import pickle
import hmac
import hashlib
from point import Point
# all of these imports are thanks to Professor Paul Lambert
from elliptic.curves import SECP_256k1, BrainPoolP256r1
from elliptic.curves import SmallWeierstrassCurveFp
from elliptic.ecc import string_to_int, int_to_string
from cipher.chacha_poly import ChaCha


def main():	
	userLocation = raw_input("Please enter the location of your known users "+ 
							 "file: ")
	myKeyFile = raw_input("Please enter the location of your public key file: ")
	
	#load the list of known users, or if none are known create an empty list
	if(os.path.isfile(userLocation)):
		users = pickle.load(open(userLocation, "r"))
	else:
		users = {}
	
	#load the list of known users, or if none are known create an empty list
	if(os.path.isfile(myKeyFile)):
		myUserKeys = pickle.load(open(myKeyFile, "r"))
	else:
		myUserKeys = {}
	
	#actual command line arguments
	while(True):
		command = raw_input("command: ")
		#allows changing user keys
		if(command == "-eU"):
			editing = raw_input("Who is the user you are editing\creating? ")
			newKeyx = raw_input("What is the new x value for this user?\n")
			newKeyy = raw_input("What is the new y value for this user?\n")
			users[editing] = Point(newKeyx, newKeyy)
			print("User updated\n")
		#remove users
		elif(command == "-rU"):
			removing = raw_input("Who is the user you wish to remove? ")
			del users[removing]
			print("User removed\n")
		#create new private key
		elif(command == "-priv"):
			curve = SECP_256k1()
			point = curve.generator()
			temp = int_to_string(int(point.x * point.y))
			privateKey = string_to_int(temp[0:16])
			myUserKeys["private"] = privateKey
			print("Your private key was created and saved")
		#create public key for user
		elif(command == "-pub"):
			#no idea how python handles variables so this
			key = Point(0,0)
			curve = SECP_256k1()
			while(True):
				needKey = raw_input("Do you wish to create a new key? (y/n)")
				if(needKey == "y"):
					temp = curve.generator()
					x = string_to_int(int_to_string(temp.x)[0:16])
					y = string_to_int(int_to_string(temp.x)[0:16])
					tempx = int_to_string(x * myUserKeys["private"])[0:16]
					tempy = int_to_string(y * myUserKeys["private"])[0:16]
					key = Point(string_to_int(tempx), string_to_int(tempy))
					print("Your public key is:\n")
					print(key)
					myUser = raw_input("What would you like to save this key " +
										"under? ")
					if(myUser == "--NA"):
						break;
					else:
						myUserKeys[myUser] = key
						break;
				elif(needKey == "n"):
					myUser = raw_input("What is the user your public key is " +
										"stored under? ")
					key = myUserKeys[myUser]
					break;
				else:
					print("Please input y/n\n")
					print("eh")
		#encrypt file
		elif(command == "-enc"):	
			fileLoc = raw_input("Location of file to encrypt: ")
			while(True):
				if(os.path.isfile(fileLoc)):
					break
				else:
					print("Please input a valid file location.\n")
					fileLoc = raw_input("Location of file to encrypt: ")
			myPrivate = myUserKeys["private"]
			recipKey = getUser(users)
			myPublic = myKey(myUserKeys)
			sharedSecret = keyAgreement(recipKey, myPrivate)
			file = open(fileLoc, "r")
			KENC = KDF(sharedSecret)
			print(KENC)
			encrypted = encrypt(file.read(), KENC)
			writing = open(fileLoc, "w")
			writing.write(str(myPublic.x) + chr(0) +  encrypted)

		#decrypt file
		elif(command == "-dec"):
			fileLoc = raw_input("Location of file to decrypt: ")
			while(True):
				if(os.path.isfile(fileLoc)):
					break
				else:
					print("Please input a valid file location.\n")
					fileLoc = raw_input("Location of file to decrypt: ")
			myPrivate = myUserKeys["private"]
			file = open(fileLoc, "r")
			decrypted = decrypt(file.read(), myPrivate)
			print(decrypted)
			open(fileLoc, "w").write(decrypted)
		elif(command == "exit"):
			break

	#updates files at the end, won't work if program crashes
	pickle.dump(users, open(userLocation, "w"))
	pickle.dump(myUserKeys, open(myKeyFile, "w"))



def myKey(myUserKeys):
	#no idea how python handles variables so this
	key = Point(0,0)
	curve = SECP_256k1()
	while(True):
		needKey = raw_input("Do you wish to create a new key? (y/n)")
		if(needKey == "y"):
			temp = curve.generator()
			x = string_to_int(int_to_string(temp.x)[0:16])
			y = string_to_int(int_to_string(temp.x)[0:16])
			key = Point(x,y)
			print("Your public key is:\n")
			print(key)
			myUser = raw_input("What would you like to save this key under? ")
			if(myUser == "--NA"):
					break;
			else:
				myUserKeys[myUser] = key
			break;
		elif(needKey == "n"):
			myUser = raw_input("What is the user your public key is stored "+
								"under? ")
			key = myUserKeys[myUser]
			break;
		else:
			print("Please input y/n\n")
	return key


def getUser(users):
	partner = raw_input("Who are you speaking to? ")
	#either get the partner key from the list or have the user input it
	if(users.has_key(partner)):
		userKey = users[partner]
	else:
		print("This user is not in your list of known users, if this is an "+ 
				"error please restart the program")
		userKeya = raw_input("Please enter the x value for the recipient's key"+
								":\n")
		userKeyb = raw_input("Please enter the y value for the recipient's key"+
								":\n")
		x = string_to_int(userKeya[0:16])
		y = string_to_int(userKeyb[0:16])
		userKey = Point(x, y)
		users[partner] = userKey
	return userKey
	

"""
This Key Agreement Function creates a shared value using the nonce and the 
partner's public key to create a shared value
@type publicKey: long
@param publicKey: the public key of the recipient
@type nonce: long
@param nonce: the nonce for this message
@rtype: long
@return: the shared secret value
"""
def keyAgreement(recipient, myPrivate):
	return recipient.getX() * myPrivate


"""
Takes the shared secret and uses HMAC and AES to create a MAC key and
symetric encryption key respectively. Returns both of these values
@type secret: long
@param secret: the shared secret between the user and recipient
@type shared: list
@param shared: list of optional additions 
@rtype: dictionary
@return: the Kmac and Kenc keys
"""
def KDF(secret):
	secret2 = int_to_string(secret)
	HMAC = hmac.new(secret2,secret2)
	return hashlib.sha256(HMAC.digest()).digest()


def decrypt(message, myPriv):
	pos = message.index(str(unichr(0)))
	sendPub = message[0:pos]
	sharedSec = string_to_int(sendPub) * myPriv
	secret2 = int_to_string(sharedSec)
	HMAC = hmac.new(secret2,secret2)
	KENC = hashlib.sha256(HMAC.digest()).digest()
	cha = ChaCha(KENC)
	return cha.decrypt(message[pos:])
		
	

"""
Encrypts the message with the given symetric key and returns the encrypted text
@type message: String
@param message: the message to be encrypted
@type key: String
@param key: the key we're encrypting to 
@rtype: String
@return: the encrypted message
"""
def encrypt(message, key):
	cha = ChaCha(key)
	return cha.encrypt(message)

main()

