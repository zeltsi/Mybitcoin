#p2pkh

version = (1).to_bytes(4, byteorder="little", signed=False)

tx_in_count = (1).to_bytes(1, byteorder="little", signed=False)

tx_in = "soon!"

tx_out_count = (1).to_bytes(1, byteorder="little", signed=False)

tx_out = "soon!"


lock_time = (0).to_bytes(4, byteorder="little", signed=False)

tx_out_value = (299000000).to_bytes(8, byteorder="little", signed=True)

tx_out_pubScript = bytes.fromhex("76a91431726579c6ab17fe2f85e236309d4c0bcff2805588ac")      
tx_out_pubScript_size = bytes.fromhex("19")

prv_tx_id = bytes.fromhex("192730e77f297a5b805fac2a833948c761e79c1d74929d170523d624d20aff193")

reversed_prv_tx_id = bytearray(prv_tx_id)

reversed_prv_tx_id.reverse()

index = (2).to_bytes(4, byteorder="little", signed=False)

sigScript_raw = bytes.fromhex("76a91486501b046d9c67aa1e361cbf49cfc6482fd16d1b88ac")

sigScript_raw_size = bytes.fromhex("19")

sequence = bytes.fromhex("ffffffff")

raw_tx = ( version
            + tx_in_count
            + reversed_prv_tx_id
            + index
            + sigScript_raw_size
            + sigScript_raw
            + sequence
            + tx_out_count
            + tx_out_value
            + tx_out_pubScript_size
            + tx_out_pubScript
            + lock_time
            
            + (1).to_bytes(4, byteorder="little", signed=False)  #hash code
    )

print(raw_tx.hex())

import hashlib

hash_1 = hashlib.sha256(raw_tx).digest()

hash_2 = hashlib.sha256(hash_1).digest()

print(hash_2.hex())


import ecdsa

privateKey = bytes.fromhex("")

sk = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)

verifying_key = sk.get_verifying_key()

public_key = bytes.fromhex("04") + verifying_key.to_string()

signature = sk.sign_digest(hash_2, sigencode = ecdsa.util.sigencode_der_canonize)

sigScript = ((len(signature) + 1).to_bytes(1, byteorder="little", signed=False)
            + signature
            + bytes.fromhex("01")
            +(len(public_key)).to_bytes(1, byteorder="little", signed=False)
            + public_key
)


sigScript_size = (int(len(sigScript))).to_bytes(1, byteorder="little", signed=False)


REAL_TX = ( version
            + tx_in_count
            + reversed_prv_tx_id
            + index
            + sigScript_size
            + sigScript
            + sequence
            + tx_out_count
            + tx_out_value
            + tx_out_pubScript_size
            + tx_out_pubScript
            + lock_time
            
                )
print(REAL_TX.hex())


hash_1 = hashlib.sha256(bytes.fromhex("0100000001e18e68f7fc653a9f3e249c887f03963bf5c8d10f8afc01944a1126af36e98a19060000008a4730440220113f91f8d10725b3a279cf4bd4de3d43c21d94210d22acde8f9e58c7240e884c022061b05a6ccdf8dbad5b34eb57ff6832eb2a7cb584b828bdd8ada6ec843438348d01410448d297e22dbd448f2a00501a6336c15b809df00228c527e4221338d0ce9999439e80f93a6b4c1e8281724967a62bcf44142d46dfc72d31f58b8304556f5f70aaffffffff01c060d211000000001976a91486501b046d9c67aa1e361cbf49cfc6482fd16d1b88ac00000000")).digest()

hash_2 = hashlib.sha256(hash_1).digest()

print(hash_2.hex())

