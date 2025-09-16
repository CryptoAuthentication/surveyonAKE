from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
import json
import random
import string
import hashlib
import time
import socket
import hmac
import string
from memory_profiler import memory_usage
from time import process_time
from datetime import datetime



def concatenate_values(sk,TS,ID_D,ED_D):
    return f"{sk}:{TS}:{ID_D}:{ED_D}".encode()

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

# Load drone keys
    with open('drone_keys.json', 'r') as f:
        drone_data = json.load(f)

    ID_D = drone_data['ID_D']

    ED_D = drone_data['ED_D']

    SK_D = group.deserialize(bytes.fromhex(drone_data['SK_D']))

# Load controller keys
    with open('controller_keys.json', 'r') as f:
        controller_data = json.load(f)

    ID_C = controller_data['ID_C']

    ED_C = controller_data['ED_C']

    PK_C = group.deserialize(bytes.fromhex(controller_data['PK_C']))

    P_pub = group.deserialize(bytes.fromhex(controller_data['P_pub']))

# Load system param P
    with open('system_params.json', 'r') as f:
        sys_params = json.load(f)

    start_CPU_time_2 = process_time() 

    P = group.deserialize(bytes.fromhex(sys_params['P']))

# Generate session key sk, timestamp TS, random x
    sk = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    TS = datetime.utcnow().strftime('%Y%m%d%H%M%S')

    x = group.random(ZR)

# Compute g = e(P, P), then r = g^x
    g = pair(P, P)

    r = g ** x

    plain_message = concatenate_values(sk,TS,ID_D,ED_D)

    H3_r = hashlib.sha256(group.serialize(r)).digest()

    H3_r_hex = H3_r.hex()

    c = int.from_bytes(plain_message, byteorder='big') ^ int.from_bytes(H3_r, byteorder='big')

# Compute h = H4(...)
    h_input = sk + TS + ID_D + ED_D + group.serialize(r).hex()

    h = group.hash(h_input, ZR)

# S and T calculations
    S = (x + h) * SK_D

    H1_IDC_EDC = group.hash(ID_C + '||' + ED_C, ZR)

    H2_PKC = group.hash(group.serialize(PK_C), ZR)

    T = x * (PK_C + H2_PKC * (H1_IDC_EDC * P + P_pub))

    end_CPU_time_2 = process_time() 
# Create a dictionary with the values to send
    data = {
        "c": c,
        "S": group.serialize(S).hex(),
        "T":  group.serialize(T).hex()
    }

#host = "192.168.1.36"
    host = "localhost"
    port = 11111


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("================================================================================================")
        print(f"----------------- Connected with Controller on {host} -----------------")

        json_data = json.dumps(data).encode('utf-8')      
        s.sendall(json_data)

        print("================================================================================================")		 

        print("----------------- Preparing Login Message -----------------")

        print("================================================================================================")

        print("/////// Sent Login Request Message <c, S, T> to Controller ///////")

        print("================================================================================================")

        print("----------------- Login Message Parameters -----------------")

        print("Sent c:", c)

        print("Sent S:", S)

        print("Sent T:", T)     

        print("================================================================================================")

        print("----------------- Waiting for Challeneg Message from Controller -----------------")

        

        

         



# Receive data from the server
        response = s.recv(1024)
        bytes_received = len(response)  # size in bytes
        response_data = json.loads(response.decode("utf-8"))

        start_CPU_time_3 = process_time() 

# Extract and print Mprj, Tidstar, and ppsi
        sk_star = response_data.get('sk_star')

        retreived_tag  = response_data.get('tag')
       

        print("================================================================================================")

        print("/////// Received Challenge Message <Tag, sk_star> from Controller ///////")

        print("================================================================================================")

        print("----------------- Received Challenge Message Parameters -----------------")

        print("Received Tag:", retreived_tag)

        print("Received sk_star:", sk_star)

        print("================================================================================================")

  

        tag_star, session_key = generate_mac(sk, sk_star, TS)

        assert tag_star == retreived_tag, f"Controller verification failed: retreived_tag != tag_start\n{sys.exit(1)}"

        print("----------------- Controller Authentication went Sucessful -----------------")

        print("================================================================================================")            
        print(f"Established Session Key with Controller: {session_key.hex()}")

        print("================================================================================================")

        end_CPU_time_3 = process_time() 
   

        end_time = time.perf_counter()	
		

        mem_after_1 = memory_usage()[0]

        total_memory_consumed = mem_after_1 - mem_before_1

        #print(f"Total memory consumed: {total_memory_consumed:.6f} MB")	

# Calculate CPU time for each function
        cpu_time_1 = end_CPU_time_1 - start_CPU_time_1 
        cpu_time_2 = end_CPU_time_2 - start_CPU_time_2
        cpu_time_3 = end_CPU_time_3 - start_CPU_time_3

# Compute total CPU time
        total_cpu_time = cpu_time_1 + cpu_time_2 + cpu_time_3	

        #print(f"Total CPU time: {total_cpu_time:.6f} seconds")		

        execution_time_sec = (end_time - start_time) 

        #print(f"Execution time: {execution_time_ms:.6f} seconds")		

# Convert to kilobytes
        kb_received = bytes_received / 1024

        print("┌───────────────────── Performance Metrics ───────────────────┐")
        print(f"│ Total Memory Consumed │ {total_memory_consumed:>10.6f} MB                       │")
        print(f"│ Total CPU Time        │ {total_cpu_time:>10.6f} s                        │")
        print(f"│ Execution Time        │ {execution_time_sec:>10.6f} s                        │")
        print(f"│ Communication Cost    │ {bytes_received} bytes ({kb_received:.3f} KB)                │")
        print("└─────────────────────────────────────────────────────────────┘")

	
        s.close()

	
if __name__ == "__main__":



    main()		
