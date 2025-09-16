import socket
import threading
import os
import hashlib
import json
from fuzzy_extractor import FuzzyExtractor
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import numpy as np
import time
import struct
import ast



def load_sk_gss():

    with open('gss_data.json', 'r') as file:

        gss_data_var = json.load(file)

        # Retrieve the SK_GSS (convert it from hex back to bytes)

        ID_GSS = gss_data_var['ID_GSS']     

        SK_GSS = gss_data_var['SK_GSS']

        CP = int(gss_data_var['CP'],16)
        
        CT_GSS = bytes.fromhex(gss_data_var['CT_GSS'])
        
        SID_i_stored = gss_data_var['SID_i']

        return SK_GSS, ID_GSS, CP, CT_GSS, SID_i_stored

def split_SID_RN(concatenate_SID_RN_data):
    decoded_data = concatenate_SID_RN_data.decode()
    SID_i, RN_1 = decoded_data.split(':')
    return SID_i, RN_1
    
def split_PT_GSS(PT_GSS):
    decoded_data = PT_GSS.decode()
    SP_i, PID_D_j, SP_j = decoded_data.split(':')
    return SP_i, PID_D_j, SP_j
    
 
    
def split_PT_3(PT_3):
    decoded_data = PT_3.decode()
    PID_D_j_EU_ret, RN_4_str = decoded_data.split(':')
    RN_4 = ast.literal_eval(RN_4_str)
    return PID_D_j_EU_ret, RN_4
    
def concate_Q_a_RN_5(Q_a, RN_5):
    return f"{Q_a}:{RN_5}".encode()  
    
    

# Function to handle messages from Client1
def handle_messages_from_client1(connection, client2_socket):
    try:
    
   
        # Receive msg1 from Client1
        msg1 = connection.recv(1024)
        if msg1:
            #print(f"Received (msg1) from User: {msg1.decode()}")

            msg1_data = msg1.decode('utf-8')
            Json_msg1_data = json.loads(msg1_data)
    
            TS_2 = Json_msg1_data.get("TS_2")
            UP_EU = int(Json_msg1_data.get("UP_EU"))
            CT_3 = bytes.fromhex(Json_msg1_data.get("CT_3"))
            RN_3 = bytes.fromhex(Json_msg1_data.get("RN_3"))
            #print(f"TS_2 :{TS_2}")
            #print(f"UP_EU :{UP_EU}")
            #print(f"CT_3 :{CT_3}")
            #print(f"RN_3 :{RN_3}")
            print("================================================================================================")
            print("/////// Received Message <TS_2, UP_EU, CT_3, RN_3> from the User ///////")
            print("================================================================================================")
            print("----------------- Received Message Parameters -----------------")
            print("TS_2", TS_2)
            print("UP_EU", UP_EU)
            print("CT_3:", CT_3.hex())
            print("RN_3:", RN_3.hex())
            print("================================================================================================")
		
            key = b'\x81\xbcg4\xbcd\xee\xe8\xed A\x86\x87\xfd\xfd\x08' 
            SK_GSS, ID_GSS, CP, CT_GSS, SID_i_stored = load_sk_gss()
            #print(f"SK_GSS:{SK_GSS}")
            #print(f"ID_GSS:{ID_GSS}")
            #print(f"CP:{CP}")


            concatenate_SID_RN = CP ^ UP_EU
            concatenate_SID_RN_data = concatenate_SID_RN.to_bytes((concatenate_SID_RN.bit_length() + 7) // 8, byteorder='big')
            SID_i,RN_1 = split_SID_RN(concatenate_SID_RN_data)
            #print(f"SID_i: {SID_i}")
            #print(f"RN_1: {RN_1}")
    
    
            zeros_bytes = b'0' * 16  # 16 bytes of zeros
            SID_i_int = int(SID_i)
            SID_i_bytes = SID_i_int.to_bytes((SID_i_int.bit_length() + 7) // 8, byteorder='big')
            #print(f"SID_i_bytes: {SID_i_bytes}")
            CP_bytes = CP.to_bytes((CP.bit_length() + 7) // 8, byteorder='big')    

            #print(f"CP_bytes  : {CP_bytes}")

            W = CP_bytes + SID_i_bytes + zeros_bytes  # Append 16 zeros

            K1 = W[:len(W)//2]

            N1 = W[len(W)//2:]

            IS_4 = K1 + N1
            #print(f"IS_4: {IS_4}")

            AD_GSS = bytes.fromhex(ID_GSS)
            #print(f"AD_GSS: {AD_GSS}")
            SK_GSS_bytes = bytes.fromhex(SK_GSS)
            SK_GSS_first_128_bits = SK_GSS_bytes[:16] 
            #print(f"SK_GSS_first_128_bits: {SK_GSS_first_128_bits}")
            aesgcm = AESGCM(SK_GSS_first_128_bits)
            #print(f"CT_GSS: {CT_GSS}")
            PT_GSS = aesgcm.decrypt(IS_4, CT_GSS, AD_GSS)
            #print(f"PT_GSS :{PT_GSS}")
    
            SP_i, PID_D_j_ret, SP_j = split_PT_GSS(PT_GSS)
    
            #print(f"PID_D_j_ret : {PID_D_j_ret}")
            #print(f"SP_i :{SP_i}")
            #print(f"SP_j :{SP_j}")

            B_2 = str(TS_2) + RN_3.hex() + RN_3.hex() 
            AD_4 = B_2 + B_2
            N_5 = str(SP_i) + RN_3.hex()  + str(TS_2) 
            #print(f"str(UP_EU) : {str(UP_EU) }")
            #print(f"RN_3.hex(): {RN_3.hex()}")
            #print(f"str(SP_i): {str(SP_i)}")
            #print(f"str(TS_2): {str(TS_2)}")
            Q = hashlib.sha1((str(UP_EU) + RN_3.hex()  + str(SP_i) + str(TS_2)).encode('utf-8')).hexdigest()
            #print(f"Q:{Q}")
            K_5 = Q[:16]
            #print(f"K_5: {K_5}")
            #print(f"N_5: {N_5}")
            IS_5 = K_5 + N_5

            if len(IS_5) % 2 != 0:
                IS_5 = '0' + IS_5  # pad with a leading 0 (safe default)
            IS_5_bytes = bytes.fromhex(IS_5)
            AD_4_bytes = bytes.fromhex(AD_4)

            aesgcm2 = AESGCM(key)  
    
            #print(f"key: {key}")
            #print(f"IS_5_bytes: {IS_5_bytes}")
            #print(f"AD_4_bytes: {AD_4_bytes}")
            #print(f"CT_3: {CT_3}")
            PT_3 = aesgcm2.decrypt(IS_5_bytes, CT_3, AD_4_bytes)
            #print(f"PT_3: {PT_3}")
    
            PID_D_j_EU_ret, RN_4 = split_PT_3(PT_3)
            #print(f"PID_D_j_EU_ret: {PID_D_j_EU_ret}")
            #print(f"RN_4: {RN_4}")

############################
            current_timestamp = int(time.time())
            TS_3 = current_timestamp & 0xFFFFFFFF  # mask to fit within 32-bit
            #print(f"TS_3: {TS_3}")
            RN_5 = os.urandom(16)
            #print(f"RN_5: {RN_5}")
            RN_6 = os.urandom(2)
            #print(f"RN_6: {RN_6}")
    
       
            Q_a = hashlib.sha1((str(UP_EU) + RN_4.hex()  + str(SP_i)).encode('utf-8')).hexdigest()
            #print(f"UP_EU: {UP_EU}") 
            #print(f"RN_4_hex: {RN_4.hex()}") 
            #print(f"SP_i: {SP_i}")     
            #print(f"Q_a: {Q_a}")    
            Q_6 = hashlib.sha1((PID_D_j_ret + str(SP_j) + str(RN_6) + str(TS_3)).encode('utf-8')).hexdigest()
            #print(f"Q_6: {Q_6}")
    
            K_6 = Q_6[:16]
            #print(f"K_6: {K_6}")
    
            N_6 = str(SP_j) + RN_6.hex()  + str(TS_3)
            #print(f"SP_j: {SP_j}")    
            #print(f"N_6: {N_6}")
    
            IS_6 = K_6 + N_6
            #print(f"IS_6: {IS_6}")
    
            B_3 = str(TS_3) + RN_6.hex() + RN_6.hex() 
            #print(f"B_3: {B_3}")
            AD_5 = B_3 + B_3
            #print(f"AD_5: {AD_5}")
    
            PT_4 = concate_Q_a_RN_5(Q_a, RN_5)
            #print(f"PT_4: {PT_4}")
    
            AD_5_bytes = bytes.fromhex(AD_5)
            IS_6_bytes = bytes.fromhex(IS_6)

            #print(f"key: {key}")
            #print(f"IS_6_bytes: {IS_6_bytes}")
            #print(f"AD_5_bytes: {AD_5_bytes}")
    
            CT_4 = aesgcm2.encrypt(IS_6_bytes, PT_4, AD_5_bytes)       

            data22 = {"TS_3": TS_3, "CT_4": CT_4.hex(), "RN_6": RN_6.hex() }
            #print(f"data22: {data22}")
            json_data = json.dumps(data22).encode('utf-8') 
            client2_socket.sendall(json_data)
            #print(f"Successfully sent Message 2 {json_data} to Drone")
            print("================================================================================================")
            print("/////// Sent Message <TS_3, CT_4, RN_6> to Drone ///////")
            print("================================================================================================")
            print("----------------- Sent Message Parameters -----------------")
            print("Sent TS_3:", TS_3)
            print("Sent CT_4:", CT_4.hex())
            print("Sent RN_6:", RN_6.hex()) 
            print("================================================================================================")
        #print("Sent RN_£:", RN_3.hex())    

    except Exception as e:
        print(f"Error handling Client1 messages: {e}")

# Function to manage communication with both clients
def manage_communication(client1_socket, client2_socket):
    # Handle messages from Client1
    handle_messages_from_client1(client1_socket, client2_socket)


# Main server script
def main():
    host = ''  # Listen on all available interfaces
    port = 11111 

    # Create server socket for listening to clients
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(2)
        #print(f"Server listening on port {port}...")
        print("================================================================================================")
        print(f"----------------- GSS is waiting for connection -----------------")
        print("================================================================================================")
        # Accept connections from Client1 and Client2
        client1_socket, client1_addr = server_socket.accept()
        print("================================================================================================")
        print(f"----------------- Connected with the User on {client1_addr} -----------------")

        client2_socket, client2_addr = server_socket.accept()
        
        print(f"----------------- Connected with Drone on {client2_addr} -----------------")
        # Start a thread to manage communication between the clients
        communication_thread = threading.Thread(target=manage_communication, args=(client1_socket, client2_socket))
        communication_thread.start()
        client1_socket.close()
        #client2_socket.close()
        print("Sockets closed.")
if __name__ == "__main__":
    main()
