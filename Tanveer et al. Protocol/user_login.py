import socket
import base64
from cryptography.fernet import Fernet
import os
import hashlib
import json
from fuzzy_extractor import FuzzyExtractor
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import numpy as np
import time
import struct
import ast

def split_PT_EU_values(plain_message):
    decoded_data = plain_message.decode()
    UP_EU, SP_i, PID_D_j = decoded_data.split(':')
    return UP_EU, SP_i, PID_D_j
    
def concate_PID_RN_4(PID_D_j, RN_4):   
    return f"{PID_D_j}:{RN_4}".encode()    

# Your custom hex string
hex_string = 'bd52568e0afb26b383dd14eeb105a6bb'

# Convert the hex string to bytes
key_bytes = bytes.fromhex(hex_string)

# Ensure the length is 32 bytes by padding with zeros or some constant
# You need 16 more bytes to reach the 32-byte length
padded_key = key_bytes.ljust(32, b'\0')

# Base64 encode the key to make it a valid Fernet key
fernet_key = base64.urlsafe_b64encode(padded_key)

# Use the generated key to create the Fernet cipher object
cipher = Fernet(fernet_key)



def communicate_with_server():
    host = '127.0.0.1'  # Localhost since Client1 is on the same laptop as the server
    port = 11111  # Port for communication with the server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("================================================================================================")
        print(f"----------------- Connected with the GSS -----------------")
        print("================================================================================================")		 
        print("----------------- Preparing Login Message -----------------")
        print("================================================================================================")
        ID_EU = "b3728ecc34f23d8ff6619a0ad838d50c"
        PS_EU = "3b1a6504b44a2b2dae8f436e31bd0391"
        EB_EU = "7d2262ab4a1e1c74"
        key = b'\x81\xbcg4\xbcd\xee\xe8\xed A\x86\x87\xfd\xfd\x08'


    #ID_EU = input("Please enter ID: ")
    #PS_EU = input("Please enter Password: ")
    #EB_EU = input("Imprint Bios: ")
        EB_EU_bytes = bytes.fromhex(EB_EU)
        with open('user_data.json', 'r') as json_file:
            stored_values = json.load(json_file)
            RN_2 = stored_values["RN_2"]
            CT_EU = stored_values["CT_EU"]
            PID_D_j = stored_values["PID_D_j"]        
            RPD_lists= stored_values["RPD_lists"]
		#converting stored values in a vector
            RPD = [np.array(arr, dtype=np.uint8) for arr in RPD_lists] 


        extractor = FuzzyExtractor(8, 8) # Create a fuzzy extractor with parameters (key length, input length)
        BK_EU = extractor.reproduce(EB_EU_bytes, RPD)
        #print(f"BK_EU: {BK_EU}")

        AD_1 = bytes.fromhex(RN_2)
        A_1 = BK_EU
        #print(f"ID_EU: {ID_EU}")
        #print(f"PS_EU: {PS_EU}")
        A_2 = int(ID_EU, 16) ^ int(PS_EU, 16)
        A_3 = int.from_bytes(A_1, byteorder='big') ^A_2
        A_3_hex = hex(A_3)[2:]  # Strip the '0x' prefix

        K_3 = A_3_hex[:len(A_3_hex)//2]

        N_3 = A_3_hex[len(A_3_hex)//2:]

        IS_EU = K_3 + N_3
    
        PS_EU_bytes = bytes.fromhex(PS_EU)    
        PS_EU_first_128_bits = PS_EU_bytes[:16]
        #PS_EU_first_128_bits_bytes = bytes.fromhex(PS_EU_first_128_bits)

        aesgcm = AESGCM(PS_EU_first_128_bits)

        IS_EU_bytes = bytes.fromhex(IS_EU)
        CT_EU_bytes = bytes.fromhex(CT_EU)    
    
        #print(f"IS_EU_bytes: {IS_EU_bytes}")   
        #print(f"CT_EU: {CT_EU}")   
        #print(f"AD_1: {AD_1}")    
        PT_EU = aesgcm.decrypt(IS_EU_bytes, CT_EU_bytes, AD_1)

        UP_EU, SP_i, PID_D_j = split_PT_EU_values(PT_EU)
    
        #print(f"UP_EU: {UP_EU}")
        #print(f"SP_i: {SP_i}")
        #print(f"PID_D_j:{PID_D_j}")
    

        current_timestamp = int(time.time())


        TS_2 = current_timestamp & 0xFFFFFFFF  # mask to fit within 32-bit
        #print(f"TS_2: {TS_2}")
        RN_3 = os.urandom(2)
        RN_4 = os.urandom(16)
    
        N_4 = str(SP_i) + RN_3.hex() + str(TS_2)
        #print(f"UP_EU:{UP_EU}")
        #print(f"RN_3:{RN_3.hex()}")
        #print(f"SP_i:{SP_i}")
        #print(f"TS_2:{str(TS_2)}")
        #print(f"str(UP_EU) : {str(UP_EU) }")
        #print(f"RN_3.hex(): {RN_3.hex()}")
        #print(f"str(SP_i): {str(SP_i)}")
        #print(f"str(TS_2): {str(TS_2)}")
        B = hashlib.sha1((str(UP_EU) + RN_3.hex() + str(SP_i) + str(TS_2)).encode('utf-8')).hexdigest()
        #print(f"B:{B}")
        K_4 = B[:16]
        #print(f"K_4: {K_4}")
        #print(f"N_4: {N_4}")
        IS_3 = K_4 + N_4
        #print(f"IS_3: {IS_3}")
        #print(f"length of IS_3 is: {len(IS_3)}")
   
        B_1 = str(TS_2) + RN_3.hex() + RN_3.hex() 

        AD_3 = B_1 + B_1
        #print(f"AD_3:{str(AD_3)}")    
        PT_3 = concate_PID_RN_4(PID_D_j, RN_4)
        #print(f"PT_3: {PT_3}")
        #print(f"RN_4: {RN_4}")
        aesgcm = AESGCM(key)  

        AD_3_bytes = bytes.fromhex(AD_3)
        if len(IS_3) % 2 != 0:
            IS_3 = '0' + IS_3  # pad with a leading 0 (safe default)
        IS_3_bytes = bytes.fromhex(IS_3)
        IS_3_bytes = bytes.fromhex(IS_3)

        #print(f"key: {key}")
        #print(f"IS_3_bytes: {IS_3_bytes}")
        #print(f"AD_3_bytes: {AD_3_bytes}")
    
        CT_3 = aesgcm.encrypt(IS_3_bytes, PT_3, AD_3_bytes)       
        #print(f"CT_3: {CT_3}")
        data = {"TS_2": TS_2, "UP_EU": UP_EU,"CT_3": CT_3.hex(), "RN_3": RN_3.hex() }
        #print(f"data: {data}")

        json_data = json.dumps(data).encode('utf-8') 
        	

        s.sendall(json_data)
        #print(f"Successfully sent Message 1 to GSS")
        print("================================================================================================")
        print("/////// Sent Login Request Message <TS_2, UP_EU, CT_3> to the GSS ///////")
        print("================================================================================================")
        print("----------------- Login Message Parameters -----------------")
        print("Sent TS_2:", TS_2)
        print("Sent UP_EU:", UP_EU)
        print("Sent CT_3:", CT_3.hex()) 
        print("Sent RN_£:", RN_3.hex())     
        return UP_EU, RN_4, SP_i, PID_D_j, key


def handle_direct_communication_with_client1(UP_EU, RN_4, SP_i, PID_D_j,key):
    host = ''  # Listen on all interfaces
    port = 22222  # Different port for direct communication

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        #print(f"Listening for direct communication on port {port}...")

        conn, addr = s.accept()
        with conn:

            print("================================================================================================")
            print("----------------- Waiting for Message from the Drone -----------------")

            msg3 = conn.recv(1024)
            #print(f"Received (msg3) from Drone: {msg3.decode()}")
            
            
            

		
# Convert the received JSON string to a Python dictionary
            msg3_data = json.loads(msg3)
    

            TS_4 = msg3_data.get("TS_4")
            CT_5 = bytes.fromhex(msg3_data.get("CT_5"))
            Q_b = msg3_data.get("Q_b")
            print("================================================================================================")
            print("/////// Received Message <TS_4, CT_5, Q_b> from Drone ///////")
            print("================================================================================================")
            print("----------------- Received Challenge Message Parameters -----------------")
            print("TS_4", TS_4)
            print("CT_5:", CT_5.hex())
            print("Q_b:", Q_b)
            print("================================================================================================")
        
            #print(f"TS_4: {TS_4}")
            #print(f"CT_5: {CT_5}")
            #print(f"Q_b: {Q_b}")
    
            Q_c = hashlib.sha1((str(UP_EU) + RN_4.hex()  + str(SP_i)).encode('utf-8')).hexdigest()
            #print(f"UP_EU: {UP_EU}") 
            #print(f"RN_4_hex: {RN_4.hex()}") 
            #print(f"SP_i: {SP_i}")  
            #print(f"Q_c: {Q_c}")
            K_9 = Q_c[:16]
            #print(f"K_9: {K_9}")
    
            N_9 = Q_b
    
            IS_9 = K_9 + N_9
            #print(f"IS_9: {IS_9}")
    
            B_6 = str(TS_4) + str(TS_4) 
            #print(f"B_6: {B_6}")
            AD_9 = B_6 + B_6
            #print(f"AD_9: {AD_9}")
    
    
            AD_9_bytes = bytes.fromhex(AD_9)
            IS_9_bytes = bytes.fromhex(IS_9)
    
            #print(f"AD_9_bytes: {AD_9_bytes}")
            #print(f"IS_9_bytes: {IS_9_bytes}")

            aesgcm2 = AESGCM(key)      
            Z_a = aesgcm2.decrypt(IS_9_bytes, CT_5, AD_9_bytes)
            #print(f"Z_a: {int.from_bytes(Z_a, byteorder='big')}")     
    

            SK = hashlib.sha1((Q_c + str(int.from_bytes(Z_a, byteorder='big')) + str(TS_4) + PID_D_j).encode('utf-8')).hexdigest()

            #print(f"SK : {SK}")
    
            Q_d = SK[:16]    
            assert Q_d == Q_b, f"Assertion failed: Q_d ({Q_d}) != Q_b ({Q_b})"

            print("----------------- Drone Authentication went Sucessful -----------------")
            print("================================================================================================")            
            print(f"Established Session Key with Drone: {SK}")
            print("================================================================================================")
            #s.close()
            #print("User's Socket closed.")

if __name__ == "__main__":
    UP_EU, RN_4, SP_i, PID_D_j, key = communicate_with_server()
    handle_direct_communication_with_client1(UP_EU, RN_4, SP_i, PID_D_j, key)
