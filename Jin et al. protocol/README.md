# Drone–Controller Secure Communication (IBC/CLC Model)

This repository contains implementations of secure protocols for **drone ↔ controller communication**.  
The system uses **Identity-Based Cryptography (IBC)** for drones and **Certificateless Cryptography (CLC)** for controllers, with a **Registration Center (RC)** that bootstraps trust.

---

## 📌 Network Model
- **Registration Center (RC)**  
  - Generates **system parameters** (elliptic curve, pairing functions, hash functions).  
  - Acts as the trusted authority for registration.  
  - Issues:
    - **Drone:** full private key derived from its identity `ID_D`.  
    - **Controller:** partial private key derived from its identity `ID_C`; controller completes its key pair with a secret of its own.  

- **Drone (IBC)**  
  - Holds an identity-based private key.  
  - Uses it to authenticate and establish secure communication with the controller.  

- **Controller (CLC)**  
  - Holds a certificateless key pair (partial key from RC + user’s secret).  
  - Uses it to mutually authenticate and establish secure communication with the drone.  

---

## 🔁 Workflow

1. **System Setup (RC)**  
   - RC generates pairing parameters `(G, e, q, H1, H2, …)` and long-term master key.  

2. **Registration**  
   - Drone registers with RC → receives full IBC private key.  
   - Controller registers with RC → receives partial private key, then combines with own secret to form full key pair.  

3. **Session Key Establishment**  
   - Drone ↔ Controller perform a **mutual handshake protocol** using their IBC and CLC credentials.  
   - Both derive the same **session key (SK)**.  

4. **Secure Data Exchange**  
   - Once SK is established, the Drone encrypts surveillance/telemetry data end-to-end using SK.  
   - Data can be transmitted securely (e.g., relayed via GSS/cloud if needed) without RC intervention.  

---

## 📂 Repository Structure
