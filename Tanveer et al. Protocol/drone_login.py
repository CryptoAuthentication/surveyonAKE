import socket
import base64
from cryptography.fernet import Fernet
import netifaces
import os
import hashlib
import json
from fuzzy_extractor import FuzzyExtractor
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import numpy as np
import time
import struct
import ast


def load_drone_data():

    with open('drone_data.json', 'r') as file:

        gss_data_var = json.load(file)
        PID_j = gss_data_var['PID_j']     
        ID_j = gss_data_var['ID_j']
        SP_j = gss_data_var['SP_j']
        return PID_j, ID_j, SP_j
        
def split_PT_4(PT_4):
    decoded_data = PT_4.decode()
    Q_a, RN_5_str = decoded_data.split(':')
    RN_5 = ast.literal_eval(RN_5_str)
    return Q_a, RN_5

#getting current ip
wifi_interface = 'wlan0'
current_ip = netifaces.ifaddresses(wifi_interface)[netifaces.AF_INET][0]['addr']

def communicate_with_server():
    host = '127.0.0.1'  # IP address of the server (Laptop-A1)
    port = 11111  # Port for communication with the server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("================================================================================================")
        print(f"----------------- Connected with the GSS -----------------")
        print("================================================================================================")		 
        print("----------------- Waiting for GSS's Message -----------------")
        # Wait for msg2 from the server
        msg2 = s.recv(1024)
        #print(f"Received (msg2) from Server: {msg2.decode()}")
        
        # Receive data from the Drone
        msg2_data = msg2.decode('utf-8')

# Convert the received JSON string to a Python dictionary
        Json_msg2_data = json.loads(msg2_data)
    
# Extract the values from json
        TS_3 = Json_msg2_data.get("TS_3")
        CT_4 = bytes.fromhex(Json_msg2_data.get("CT_4"))
        RN_6 = bytes.fromhex(Json_msg2_data.get("RN_6"))
        #print(f"TS_3 :{TS_3}")
        #print(f"CT_4 :{CT_4}")
        #print(f"RN_6 :{RN_6}")
        print("================================================================================================")
        print("/////// Received Message <TS_3, CT_4, RN_6> from the USer ///////")
        print("================================================================================================")
        print("----------------- Received Message Parameters -----------------")
        print("TS_3", TS_3)
        print("CT_4:", CT_4.hex())
        print("RN_6:", RN_6.hex())
        print("================================================================================================")        
        key = b'\x81\xbcg4\xbcd\xee\xe8\xed A\x86\x87\xfd\xfd\x08' 
        PID_j, ID_j, SP_j = load_drone_data()
        #print(f"PID_j:{PID_j}")
        #print(f"ID_j:{ID_j}")
        #print(f"SP_j:{SP_j}")

        Q_7 = hashlib.sha1((PID_j + str(SP_j) + str(RN_6) + str(TS_3)).encode('utf-8')).hexdigest()
        #print(f"Q_7: {Q_7}")
        N_7 = str(SP_j) + RN_6.hex()  + str(TS_3)
        #print(f"N_7: {N_7}")
        K_7 = Q_7[:16]
        #print(f"K_7: {K_7}")
        B_4 = str(TS_3) + RN_6.hex() + RN_6.hex() 
        #print(f"B_4: {B_4}")
        AD_6 = B_4 + B_4
        #print(f"AD_6: {AD_6}")
    
        IS_7 = K_7 + N_7
        #print(f"IS_7: {IS_7}")

        AD_6_bytes = bytes.fromhex(AD_6)
        IS_7_bytes = bytes.fromhex(IS_7)

        #print(f"key: {key}")
        #print(f"IS_7_bytes: {IS_7_bytes}")
        #print(f"AD_6_bytes: {AD_6_bytes}")
    
        aesgcm2 = AESGCM(key)  
    
        PT_4 = aesgcm2.decrypt(IS_7_bytes, CT_4, AD_6_bytes)
    
        #print(f"PT_4: {PT_4}")
        Q_a, RN_5 = split_PT_4(PT_4)
        #print(f"Q_a: {Q_a}")
        #print(f"RN_5: {RN_5}")

        current_timestamp = int(time.time())
        TS_4 = current_timestamp & 0xFFFFFFFF  # mask to fit within 32-bit
        #print(f"TS_4: {TS_4}")
        RN_7 = os.urandom(16)
        #print(f"RN_7: {RN_7}")

        xor_RN_5_6 = int.from_bytes(RN_5,byteorder = 'big') ^ int.from_bytes(RN_6,byteorder = 'big')
        #print(f"xor_RN_5_6 : {xor_RN_5_6}")
    

        SK = hashlib.sha1((Q_a + str(xor_RN_5_6) + str(TS_4) + PID_j).encode('utf-8')).hexdigest()

        #print(f"SK : {SK}")
    
        Q_b = SK[:16]
        #print(f"Q_b: {Q_b}")
    
        K_8 = Q_a[:16]
        #print(f"K_8: {K_8}")
    
        N_8 = Q_b
    
        IS_8 = K_8 + N_8
        #print(f"IS_8: {IS_8}")
    
        B_5 = str(TS_4) + str(TS_4) 
        #print(f"B_5: {B_5}")
        AD_8 = B_5 + B_5
        #print(f"AD_8: {AD_8}")
    

    
        AD_8_bytes = bytes.fromhex(AD_8)
        IS_8_bytes = bytes.fromhex(IS_8)

        Z_a = int.from_bytes(RN_5,byteorder = 'big') ^ int.from_bytes(RN_6,byteorder = 'big')
        #print(f"Z_a: {Z_a}")    
        byte_length = (Z_a.bit_length() + 7) // 8

# Convert the integer to bytes
        Z_a_bytes = Z_a.to_bytes(byte_length, byteorder='big')

    #print(f"key: {key}")
        #print(f"Z_a_bytes: {Z_a_bytes}")
        #print(f"AD_8_bytes: {AD_8_bytes}")
        #print(f"IS_8_bytes: {IS_8_bytes}")    
    
    
        CT_5 = aesgcm2.encrypt(IS_8_bytes, Z_a_bytes, AD_8_bytes)
        #print(f"CT_4: {CT_4}")
        #print(f"Established SK with User is: {SK}")

        #data33 = {"TS_4": TS_4, "Q_b": Q_b, "CT_5": CT_5.hex() }
        #print(f"data: {data33}")
        return TS_4, Q_b, CT_5, SK


def direct_communication_with_client2(TS_4, Q_b, CT_5, SK):
    host = '127.0.0.1' 
    port = 22222 

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        #print("Direct connection with the User established.")
        print("================================================================================================")
        print("----------------- Waiting for User's Message -----------------")
        data22 = {"TS_4": TS_4, "Q_b": Q_b, "CT_5": CT_5.hex() }
        #print(f"data22: {data22}")
        json_data = json.dumps(data22).encode('utf-8') 
        s.sendall(json_data)
        print("================================================================================================")
        print("/////// Received Message <TS_4, CT_5, Q_b> from the User ///////")
        print("================================================================================================")
        print("----------------- Received Message Parameters -----------------")
        print("Sent TS_4:", TS_4)
        print("Sent CT_5:", CT_5.hex())
        print("Sent Q_b:", Q_b) 
        print("================================================================================================")            
        print(f"Established Session Key with User: {SK}")
        print("================================================================================================")
if __name__ == "__main__":
    TS_4, Q_b, CT_5, SK = communicate_with_server()
    #print("Now trying to connect with the User")
    direct_communication_with_client2(TS_4, Q_b, CT_5,SK)
    
