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

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = "SWI"
APmac       = a2b_hex("cebcc8fdcab7")
Clientmac   = a2b_hex("0013efd015bd")

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
SNonce      = a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = "36eef66540fa801ceee2fea9b7929b40"

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

print("\n\nValues used to derivate keys")
print("============================")
print("Passphrase: ",passPhrase,"\n")
print("SSID: ",ssid,"\n")
print("AP Mac: ",b2a_hex(APmac),"\n")
print("Client Mac: ",b2a_hex(Clientmac),"\n")
print("AP Nonce: ",b2a_hex(ANonce),"\n")
print("Client Nonce: ",b2a_hex(SNonce),"\n")

print("\n\n***************************** Test lecture passphrase *****************************")


# Récupération des valeurs écrites en dure
print("\n\nPrint en recupérant les données de wpa")
print("============================")
print("SSID: ", wpa[0].info)
print("AP Mac: ", wpa[0].addr2)
# addr2 Adresse source, addr1 adresse de destination
print("Client Mac: ", wpa[1].addr1)
# La trame 6 (wpa[5]) du fichier wpa_handshake.cap contient le Nonce de l'AP
print("AP Nonce: ", wpa[5].load.encode('hex')[26:90])

# La trame 7 (wpa[6]) du fichier wpa_handshake.cap contient le Nonce du client
print("Client Nonce: ", wpa[6].load.encode('hex')[26:90])


#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(a2b_hex(pmk),A,B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print("\nResults of the key expansion")
print("=============================")
print("PMK: ", pmk)
print("PTK: ", b2a_hex(ptk))
print("KCK: ", b2a_hex(ptk[0:16]))
print("KEK: ", b2a_hex(ptk[16:32]))
print("TK: ", b2a_hex(ptk[32:48]))
print("MICK: ", b2a_hex(ptk[48:64]))
print("MIC: ", mic.hexdigest())