# Drone Surveillance System - Protocol Implementations

This repository contains implementations of secure protocols for **drone ↔ remote-user surveillance** workflows.  
The system is built around a **Global Security Service (GSS)** that bootstraps system parameters, performs registration, and mediates login requests; after mediation, the **Drone** and **Remote User** perform mutual authentication and establish session keys for data exchange.

---

## 📌 High-level architecture & roles

- **GSS (Global Security Service)**  
  - Generates system-wide parameters (curve, hash, KDF, long-term key material).  
  - Acts as the *registration authority*: registers drones and remote users, issues credentials (e.g., identity-based private keys, partial keys, certificates).  
  - Authenticates remote-user login requests and forwards them to the intended drone (acting as a secure mediator/dispatcher).  
  - Not in the data plane after successful authentication: it does **not** remain on the critical path for the AKE or data stream.

- **Drone**  
  - Registered with GSS and provisioned with long-term credentials.  
  - Authenticates requests forwarded by GSS and engages in direct mutual authentication + AKE with the remote user.  
  - Provides surveillance/telemetry data after successful authentication and session key establishment.

- **Remote User**  
  - Registered with GSS and provisioned with credentials.  
  - Initiates login to request access to a drone’s surveillance data.  
  - After GSS forwards and drone confirms, performs the AKE with the drone and receives encrypted data.

---

## 🔁 End-to-end message flow (concise)

1. **System bootstrap** (one-time / GSS)  
   - GSS → generate system parameters (`Hash`, `KDF`, GSS long-term key material).

2. **Registration (off-line / provisioning)**  
   - Drone registers with GSS → receives long-term credential (e.g., IBC private key or cert).  
   - Remote User registers with GSS → receives credential (cert or partial private key).

3. **Login / Access Request**  
   - Remote User → sends login request to **GSS** (contains `ID_user`, intended `ID_drone`, proof-of-possession or signature).

4. **GSS Authentication & Forwarding**  
   - GSS authenticates the user (verifies credentials).  
   - If OK, GSS forwards an authenticated request/notification to the intended **Drone** (including metadata needed by the drone to continue).

5. **Drone-side verification**  
   - Drone verifies GSS-signed forwarding message and the identity of the requesting user (as forwarded).  
   - Drone may optionally consult local policy / ACLs.

6. **Mutual AKE — Drone ↔ Remote User**  
   - Upon acceptance, **Drone** and **Remote User** run an authenticated key exchange (ephemeral keys + long-term credentials) to derive a fresh session key `SK`.  
   - This AKE provides entity authentication, forward secrecy, replay protection, and explicit key confirmation.

7. **Data Exchange**  
   - Drone → encrypts telemetry / surveillance data with `SK` and sends to Remote User.  
   - Remote User decrypts and consumes data.

8. **Audit & Logging (optional)**  
   - GSS / Drone / User may log the event for accountability. GSS can retain metadata about the session for auditing (not the data stream).


