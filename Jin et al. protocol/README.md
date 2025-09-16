# Drone ↔ Controller Authenticated Key Exchange (AKE)

This module implements the AKE leg between a **Drone (IBC)** and a **Controller (CLC)** from the network model.  
The Registration Center (RC) is used only for **bootstrapping** identities/keys; the online AKE is strictly **Drone ↔ Controller**.

## Roles & Trust
- **Drone (IBC):** holds an identity-based private key `SK_D` issued by RC.
- **Controller (CLC):** holds a certificateless key pair `(sk_C, pk_C)` and a **partial private key** from RC.
- **RC:** offline/initialization authority only; not on the critical path of AKE.

## Protocol Goal
Mutual authentication and establishment of a fresh **session key `K_s`** between Drone and Controller with:
- entity authentication
- forward secrecy (ephemeral keys)
- resistance to replay, KCI, and impersonation
- explicit key confirmation

## Quick Start
1. Generate or import keys (once):
   - `RC` issues Drone’s IBC `SK_D` and Controller’s partial key.
   - Controller completes its full key (`sk_C, pk_C`).
2. Run demo:
   - `scripts/run-local.sh` (or see commands below)
3. On success you’ll see:
   - transcript log
   - derived session key material (hex)
   - AEAD test encrypt/decrypt

## Build & Run
- Language/Runtime: <fill in, e.g., Python 3.11 / Go 1.22 / C++20>
- Crypto libs: <fill in, e.g., libsodium/OpenSSL/pyca>
- Commands:
```bash
# example placeholders
# 1) bootstrap (mock RC)
python src/rc/registrar.py --out A1/src/drone/keystore --ctrl A1/src/controller/keystore
# 2) run AKE
python src/controller/client.py --connect localhost:5001
python src/drone/client.py --listen :5001
