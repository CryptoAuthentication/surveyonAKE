import socket
from charm.toolbox.pairinggroup import PairingGroup, ZR, pair
import json
import hashlib
import hmac
import hashlib
import random
import string
import socket
import time
from memory_profiler import memory_usage
from time import process_time

def split_values(plain_message):
    decoded_data = plain_message.decode()
    sk, TS, ID_D, ED_D = decoded_data.split(':')
    return sk, TS, ID_D, ED_D

# Function to generate the MAC tag with XOR key combination
def generate_mac(sk, sk_star,TS ):
# XOR the secret key (sk) with its variant (sk*)
    combined_key = bytes([a ^ b for a, b in zip(sk.encode(), sk_star.encode())])

# Create the HMAC object using the combined secret key and timestamp
    mac = hmac.new(combined_key, TS.encode(), hashlib.sha256)

# Return the MAC tag, sk, sk*, and TS for reference
    return mac.hexdigest(), combined_key

def main():
    start_time = time.perf_counter()	

    mem_before_1 = memory_usage()[0]

    start_CPU_time_1 = process_time() 
    group = PairingGroup('SS512')
    end_CPU_time_1 = process_time()	
    host = ''
    port = 11111


# Create a socket object and bind it to the host and port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.bind((host, port))  # Corrected the missing closing parenthesis
        s.listen()
     
# Accept a connection when a client connects
        conn, addr = s.accept()

        with conn:
            print("================================================================================================")
            print(f"-------------- Connected with Drone on {addr} -------------- ")


            print("================================================================================================")
            print("-------------- Waiting for Login message from Drone -------------- ")

################################# Receive M1 ######################################			
# Receive data from the Drone
            data = conn.recv(1024)
            bytes_received = len(data)  # size in bytes
            data = data.decode('utf-8')

# Convert the received JSON string to a Python dictionary
            received_data = json.loads(data)

# Extract and print tidi, varphii, chii, and psii
            c = received_data.get('c')

            S = group.deserialize(bytes.fromhex(received_data.get('S')))

            T = group.deserialize(bytes.fromhex(received_data.get('T')))

            print("================================================================================================")
            print("///// Received login message <c, S, T> from Drone ////")
            print("-------------- Received login message Paremeters --------------")			
            print("Received c: ", c)
            print("Received S: ", S)
            print("Received T: ", T)


##################################################################################
# Load controller's SK_C
            with open('controller_keys.json', 'r') as f:
                controller_data = json.load(f)

            SK_C = group.deserialize(bytes.fromhex(controller_data['SK_C']))

            with open('system_params.json', 'r') as f:
                sys_params = json.load(f)
            start_CPU_time_2 = process_time()
            P = group.deserialize(bytes.fromhex(sys_params['P']))

            P_pub = group.deserialize(bytes.fromhex(controller_data['P_pub']))

# Step 1: Compute r = e(T, SK_C)
            r = pair(T, SK_C)

# Step 2: Compute H3(r)
            H3_r_computed = hashlib.sha256(group.serialize(r)).digest()

#recovered_bytes = bytes([a ^ b for a, b in zip(c_bytes, H3_r_stored)])
            plain_message = c ^ int.from_bytes(H3_r_computed, byteorder='big')
            retrieved_combined_data = plain_message.to_bytes((plain_message.bit_length() + 7) // 8, byteorder='big')
            sk, TS, ID_D, ED_D = split_values(retrieved_combined_data)

# Step 3: Compute h = H4(sk || TS || ID_D || ED_D || r)
            h_input = sk + TS + ID_D + ED_D + group.serialize(r).hex()
            h = group.hash(h_input, ZR)

# Step 4: Verify e(S, H1(ID_D || ED_D) * P + P_pub) * g^(-h) == r
            H1_ID_ED = group.hash(ID_D + '||' + ED_D, ZR)

# Compute left side: e(S, H1*P + P_pub) * g^-h
            left = pair(S, H1_ID_ED * P + P_pub)
            g = pair(P, P)
            adjusted_left = left * (g ** -h)

# r = e(T, SK_C) is already computed
            if adjusted_left == r:
                print("================================================================================================")				

                print("-------------- Successful Drone Auhtentication -------------- ")

            else:
                print("================================================================================================")		
                print("-------------- Unsuccessful Drone Auhtentication -------------- ")

# Generate sk*
            sk_star = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# Example usage
            tag, session_key = generate_mac(sk, sk_star, TS)
            
            end_CPU_time_2 = process_time()
            response_data = {

            'sk_star': sk_star,

            'tag': tag}

# Convert the response data to a JSON string
            response_json = json.dumps(response_data)

# Send the response to the client
            conn.send(response_json.encode('utf-8'))

            print("================================================================================================")			
            print("///// Sent Challenge Message <Tag, sk_star> to Drone ///// ")
            print("================================================================================================")	
            print("Sent Challenge Message Paremeters")			
            print("Sent Tag: ", tag )
            print("Sent sk_star: ", sk_star)
            print("================================================================================================")    

            print(f"Established Session Key with Drone: {session_key}")
            print("================================================================================================")            

   

            end_time = time.perf_counter()	
		

            mem_after_1 = memory_usage()[0]

            total_memory_consumed = mem_after_1 - mem_before_1

            #print(f"Total memory consumed: {total_memory_consumed:.6f} MB")	

# Calculate CPU time for each function
            cpu_time_1 = end_CPU_time_1 - start_CPU_time_1 

            cpu_time_2 = end_CPU_time_2 - start_CPU_time_2

# Compute total CPU time
            total_cpu_time = cpu_time_1 + cpu_time_2 

            #print(f"Total CPU time: {total_cpu_time:.6f} seconds")		

            execution_time_sec = (end_time - start_time) 

            #print(f"Execution time: {execution_time_ms:.6f} seconds")

# Convert to kilobytes
            kb_received = bytes_received / 1024
		
            print("│----------------- Performance Metrics -----------------│")
            print(f"│ Total Memory Consumed │ {total_memory_consumed:>10.6f} MB │")
            print(f"│ Total CPU Time        │ {total_cpu_time:>10.6f} s  │")
            print(f"│ Execution Time        │ {execution_time_sec:>10.6f} s  │")
            print(f"│ Communication Cost    │ {bytes_received} bytes ({kb_received:.3f} KB)                │")
            print("└----------------- ----------------- ----------------- -┘")
            s.close()
if __name__ == "__main__":

    main()
