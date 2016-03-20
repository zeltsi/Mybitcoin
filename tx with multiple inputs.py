# Alice -> (5BTC) Bob -> Charlie

# statment(0): I'm Dan and I gave 5 BTC to Alice
# statment(1): I'm Alice and I gave 5 BTC to Bob
# statment(2): I'm Bob and I gave 5 BTC to Charlie

import struct
import base58
import hashlib
import ecdsa

Bob_addr 		= "1NWzVg38ggPoVGAG2VWt6ktdWMaV6S1pJK"
Bob_hashed_pubkey = base58.b58decode_check(Bob_addr)[1:].encode("hex")


Bob_privte_key 	= "CF933A6C602069F1CBC85990DF087714D7E86DF0D0E48398B7D8953E1F03534A"
				   
Charlie_addr 	= "17X4s8JdSdLxFyraNUDBzgmnSNeZpjm42g"
Charlie_hashed_pubkey = base58.b58decode_check(Charlie_addr)[1:].encode("hex")

txid1			= "3df07acef5b210d34c9dfe69708cc26d0f8e11a63ee1886973b30f4ff196fcd6"

txid2			= "dc335bda9f4a39243e175b02d44ad454ee5b56b211da8a9aab9cd025687109bc"

def flip_byte_order(string):
	flipped = "".join(reversed([string[i:i+2] for i in range(0, len(string), 2)]))
	return flipped

# Total amount 0.00148156 BTC
# Bob wants to send Charlie 0.001 BTC and he wants to leave 0.0002 which means Bob will get back (change) 0.00028156

to_Charlie		=	0.98156 #BTC
to_Bob			= 	0.00028156 #BTC (this is the change)

class raw_tx:
	version 		= struct.pack("<L", 1)
	tx_in_count		= struct.pack("<B", 2)
	txin1 			= {} #temp
	txin2 			= {} #temp
	tx_out_count	= struct.pack("<B", 2)
	tx_out1 		= {} #temp
	tx_out2 		= {} #temp
	lock_time		= struct.pack("<L", 0)

	hash_code		= struct.pack("<L", 1)


rtx = raw_tx()

rtx.txin1["outpoint"] 		= flip_byte_order(txid1).decode("hex")
rtx.txin1["outpoint_index"] = struct.pack("<L", 0)
rtx.txin1["script_bytes"]	= 0 #tem
rtx.txin1["script"]			= ("76a914%s88ac" % Bob_hashed_pubkey).decode("hex")
rtx.txin1["script_bytes"]	= struct.pack("<B", (len(rtx.txin1["script"])))
rtx.txin1["sequence"]		= "ffffffff".decode("hex")



rtx.txin2["outpoint"] 		= flip_byte_order(txid2).decode("hex")
rtx.txin2["outpoint_index"] = struct.pack("<L", 1)
rtx.txin2["script_bytes"]	= 0 #temp
rtx.txin2["script"]			= ("76a914%s88ac" % Bob_hashed_pubkey).decode("hex")
rtx.txin2["script_bytes"]	= struct.pack("<B", (len(rtx.txin2["script"])))
rtx.txin2["sequence"]		= "ffffffff".decode("hex")


rtx.tx_out1["value"]		= struct.pack("<Q", 100000) #send to Charlie
rtx.tx_out1["pk_script_bytes"] = 0 #temp
rtx.tx_out1["script"]		= ("76a914%s88ac" % Charlie_hashed_pubkey).decode("hex")
rtx.tx_out1["pk_script_bytes"] = struct.pack("<B", (len(rtx.tx_out1["script"])))



rtx.tx_out2["value"]		= struct.pack("<Q", 28156) #change back to Bob
rtx.tx_out2["pk_script_bytes"] = 0 #temp
rtx.tx_out2["script"]		= ("76a914%s88ac" % Bob_hashed_pubkey).decode("hex")
rtx.tx_out2["pk_script_bytes"] = struct.pack("<B", (len(rtx.tx_out2["script"])))

tx_to_sign1 = (

	rtx.version
	+ rtx.tx_in_count
	+ rtx.txin1["outpoint"]
	+ rtx.txin1["outpoint_index"]
	+ rtx.txin1["script_bytes"]
	+ rtx.txin1["script"]
	+ rtx.txin1["sequence"]
	+ rtx.txin2["outpoint"]
	+ rtx.txin2["outpoint_index"]
	+ struct.pack("<B",0)
	+ "".decode("hex")

	+ rtx.txin2["sequence"]
	+ rtx.tx_out_count
	+ rtx.tx_out1["value"]
	+ rtx.tx_out1["pk_script_bytes"]
	+ rtx.tx_out1["script"]
	+ rtx.tx_out2["value"]
	+ rtx.tx_out2["pk_script_bytes"]
	+ rtx.tx_out2["script"]
	+ rtx.lock_time
	+rtx.hash_code

	)


tx_to_sign2 = (

	rtx.version
	+ rtx.tx_in_count
	+ rtx.txin1["outpoint"]
	+ rtx.txin1["outpoint_index"]
	+ struct.pack("<B",0)
	+ "".decode("hex")

	+ rtx.txin1["sequence"]
	+ rtx.txin2["outpoint"]
	+ rtx.txin2["outpoint_index"]
	+ rtx.txin2["script_bytes"]
	+ rtx.txin2["script"]
	+ rtx.txin2["sequence"]
	+ rtx.tx_out_count
	+ rtx.tx_out1["value"]
	+ rtx.tx_out1["pk_script_bytes"]
	+ rtx.tx_out1["script"]
	+ rtx.tx_out2["value"]
	+ rtx.tx_out2["pk_script_bytes"]
	+ rtx.tx_out2["script"]
	+ rtx.lock_time
	+rtx.hash_code

	)


hashed_tx1 = hashlib.sha256(hashlib.sha256(tx_to_sign1).digest()).digest()

hashed_tx2 = hashlib.sha256(hashlib.sha256(tx_to_sign2).digest()).digest()

sk = ecdsa.SigningKey.from_string(Bob_privte_key.decode("hex"), curve = ecdsa.SECP256k1)

vk = sk.verifying_key

public_key = ('\04' + vk.to_string()).encode("hex")

signature1 = sk.sign_digest(hashed_tx1, sigencode = ecdsa.util.sigencode_der)

signature2 = sk.sign_digest(hashed_tx2, sigencode = ecdsa.util.sigencode_der)

#print "signature:" + signature.encode("hex")

sigscript1 = (
	signature1
	+ '\01'
	+ struct.pack("<B", len(public_key.decode("hex")))
	+ public_key.decode("hex")
	)


sigscript2 = (
	signature2
	+ '\01'
	+ struct.pack("<B", len(public_key.decode("hex")))
	+ public_key.decode("hex")
	)

#print "sigscript:" + sigscript.encode("hex")

real_tx = (

	rtx.version
	+ rtx.tx_in_count
	+ rtx.txin1["outpoint"]
	+ rtx.txin1["outpoint_index"]
	+ struct.pack("<B", (len(sigscript1) + 1))
	+ struct.pack("<B", len(signature1) + 1)
	+ sigscript1
	+ rtx.txin1["sequence"]
	+ rtx.txin2["outpoint"]
	+ rtx.txin2["outpoint_index"]
	+ struct.pack("<B", (len(sigscript2) + 1))
	+ struct.pack("<B", len(signature2) + 1)
	+ sigscript2
	+ rtx.txin2["sequence"]
	+ rtx.tx_out_count
	+ rtx.tx_out1["value"]
	+ rtx.tx_out1["pk_script_bytes"]
	+ rtx.tx_out1["script"]
	+ rtx.tx_out2["value"]
	+ rtx.tx_out2["pk_script_bytes"]
	+ rtx.tx_out2["script"]
	+ rtx.lock_time
	
)			#yay!

print real_tx.encode("hex")


# 01000000
# 02
# d6fc96f14f0fb3736988e13ea6118e0f6dc28c7069fe9d4cd310b2f5ce7af03d
# 01000000
# 1976a914ec06b2bf18c89706855f761d215f21f3315b399488ac
# ffffffff
# bc09716825d09cab9a8ada11b2565bee54d44ad4025b173e24394a9fda5b33dc
# 02000000
# 1976a914ec06b2bf18c89706855f761d215f21f3315b399488ac
# ffffffff
# 02a0860100000000001976a914478075922af41fb441aa0ab67e91aef27ef1e68688acfc6d0000000000001976a914ec06b2bf18c89706855f761d215f21f3315b399488ac0000000001000000


# 01000000
# 02
# d6fc96f14f0fb3736988e13ea6118e0f6dc28c7069fe9d4cd310b2f5ce7af03d
# 01000000
# 8b48 304502204b62af43e68b7243dd225bd1543877a5f5147656508b43a8fba62bfd6e28f92a022100ae0791df4adac6c212834e42b4e42dbea04df11883d493cedfd5d7876738403e
# 0141
# 0437078f8c4a54b67cd1724a3535cb1918bca186c7a143459c9aac35113d4a958b0d4eea6b320fa82c17147b72e0fe11c08b0054897ffb7bdb194f259b0db9e129
# ffffffff
# bc09716825d09cab9a8ada11b2565bee54d44ad4025b173e24394a9fda5b33dc
# 02000000
# 8b48 304502204b62af43e68b7243dd225bd1543877a5f5147656508b43a8fba62bfd6e28f92a022100ae0791df4adac6c212834e42b4e42dbea04df11883d493cedfd5d7876738403e
# 0141
# 0437078f8c4a54b67cd1724a3535cb1918bca186c7a143459c9aac35113d4a958b0d4eea6b320fa82c17147b72e0fe11c08b0054897ffb7bdb194f259b0db9e129
# ffffffff
# 02
# a086010000000000
# 1976a914478075922af41fb441aa0ab67e91aef27ef1e68688ac
# fc6d000000000000
# 1976a914ec06b2bf18c89706855f761d215f21f3315b399488ac
# 00000000

# Alice -> (5BTC) Bob -> Charlie

# statment(0): I'm Dan and I gave 5 BTC to Alice
# statment(1): I'm Alice and I gave 5 BTC to Bob
# statment(2): I'm Bob and I gave 5 BTC to Charlie

import struct
import base58
import hashlib
import ecdsa

Bob_addr 		= "1NWzVg38ggPoVGAG2VWt6ktdWMaV6S1pJK"
Bob_hashed_pubkey = base58.b58decode_check(Bob_addr)[1:].encode("hex")


Bob_privte_key 	= "CF933A6C602069F1CBC85990DF087714D7E86DF0D0E48398B7D8953E1F03534A"
				   
Charlie_private_key = "73356839c2883cdf723b44f329928d5acd51e0b3b9d88ea3e1639e34e1dc6958"

Charlie_addr 	= "17X4s8JdSdLxFyraNUDBzgmnSNeZpjm42g"
Charlie_hashed_pubkey = base58.b58decode_check(Charlie_addr)[1:].encode("hex")

txid1			= "f1abfcc876854c5bd5a68c1f6fcb1efd9ccf480476a5e896e7a93ada271aee9e"

txid2			= "dc335bda9f4a39243e175b02d44ad454ee5b56b211da8a9aab9cd025687109bc"

def flip_byte_order(string):
	flipped = "".join(reversed([string[i:i+2] for i in range(0, len(string), 2)]))
	return flipped

# Total amount 0.00148156 BTC
# Bob wants to send Charlie 0.001 BTC and he wants to leave 0.0002 which means Bob will get back (change) 0.00028156

to_Charlie		=	0.98156 #BTC
to_Bob			= 	0.00028156 #BTC (this is the change)

class raw_tx:
	version 		= struct.pack("<L", 1)
	tx_in_count		= struct.pack("<B", 2)
	txin1 			= {} #temp
	txin2 			= {} #temp
	tx_out_count	= struct.pack("<B", 1)
	tx_out1 		= {} #temp
	tx_out2 		= {} #temp
	lock_time		= struct.pack("<L", 0)

	hash_code		= struct.pack("<L", 1)


rtx = raw_tx()

rtx.txin1["outpoint"] 		= flip_byte_order(txid1).decode("hex")
rtx.txin1["outpoint_index"] = struct.pack("<L", 0)
rtx.txin1["script_bytes"]	= 0 #tem
rtx.txin1["script"]			= ("76a914%s88ac" % Charlie_hashed_pubkey).decode("hex")
rtx.txin1["script_bytes"]	= struct.pack("<B", (len(rtx.txin1["script"])))
rtx.txin1["sequence"]		= "ffffffff".decode("hex")



rtx.txin2["outpoint"] 		= flip_byte_order(txid1).decode("hex")
rtx.txin2["outpoint_index"] = struct.pack("<L", 1)
rtx.txin2["script_bytes"]	= 0 #temp
rtx.txin2["script"]			= ("76a914%s88ac" % Bob_hashed_pubkey).decode("hex")
rtx.txin2["script_bytes"]	= struct.pack("<B", (len(rtx.txin2["script"])))
rtx.txin2["sequence"]		= "ffffffff".decode("hex")


rtx.tx_out2["value"]		= struct.pack("<Q", 110000) #change back to Bob
rtx.tx_out2["pk_script_bytes"] = 0 #temp
rtx.tx_out2["script"]		= ("76a914%s88ac" % Bob_hashed_pubkey).decode("hex")
rtx.tx_out2["pk_script_bytes"] = struct.pack("<B", (len(rtx.tx_out2["script"])))

tx_to_sign1 = (

	rtx.version
	+ rtx.tx_in_count
	+ rtx.txin1["outpoint"]
	+ rtx.txin1["outpoint_index"]
	+ rtx.txin1["script_bytes"]
	+ rtx.txin1["script"]
	+ rtx.txin1["sequence"]
	+ rtx.txin2["outpoint"]
	+ rtx.txin2["outpoint_index"]
	+ struct.pack("<B",0)
	+ "".decode("hex")

	+ rtx.txin2["sequence"]
	+ rtx.tx_out_count
	+ rtx.tx_out2["value"]
	+ rtx.tx_out2["pk_script_bytes"]
	+ rtx.tx_out2["script"]
	+ rtx.lock_time
	+rtx.hash_code

	)


tx_to_sign2 = (

	rtx.version
	+ rtx.tx_in_count
	+ rtx.txin1["outpoint"]
	+ rtx.txin1["outpoint_index"]
	+ struct.pack("<B",0)
	+ "".decode("hex")

	+ rtx.txin1["sequence"]
	+ rtx.txin2["outpoint"]
	+ rtx.txin2["outpoint_index"]
	+ rtx.txin2["script_bytes"]
	+ rtx.txin2["script"]
	+ rtx.txin2["sequence"]
	+ rtx.tx_out_count
	+ rtx.tx_out2["value"]
	+ rtx.tx_out2["pk_script_bytes"]
	+ rtx.tx_out2["script"]
	+ rtx.lock_time
	+rtx.hash_code

	)


hashed_tx1 = hashlib.sha256(hashlib.sha256(tx_to_sign1).digest()).digest()

hashed_tx2 = hashlib.sha256(hashlib.sha256(tx_to_sign2).digest()).digest()

bob_sk = ecdsa.SigningKey.from_string(Bob_privte_key.decode("hex"), curve = ecdsa.SECP256k1)

bob_vk = bob_sk.verifying_key

bob_public_key = ('\04' + bob_vk.to_string()).encode("hex")




charlie_sk = ecdsa.SigningKey.from_string(Charlie_private_key.decode("hex"), curve = ecdsa.SECP256k1)

charlie_vk = charlie_sk.verifying_key

charlie_public_key = ('\04' + charlie_vk.to_string()).encode("hex")

signature1 = charlie_sk.sign_digest(hashed_tx1, sigencode = ecdsa.util.sigencode_der)

signature2 = bob_sk.sign_digest(hashed_tx2, sigencode = ecdsa.util.sigencode_der)

#print "signature:" + signature.encode("hex")

sigscript1 = (
	signature1
	+ '\01'
	+ struct.pack("<B", len(charlie_public_key.decode("hex")))
	+ charlie_public_key.decode("hex")
	)


sigscript2 = (
	signature2
	+ '\01'
	+ struct.pack("<B", len(bob_public_key.decode("hex")))
	+ bob_public_key.decode("hex")
	)

#print "sigscript:" + sigscript.encode("hex")

real_tx = (

	rtx.version
	+ rtx.tx_in_count
	+ rtx.txin1["outpoint"]
	+ rtx.txin1["outpoint_index"]
	+ struct.pack("<B", (len(sigscript1) + 1))
	+ struct.pack("<B", len(signature1) + 1)
	+ sigscript1
	+ rtx.txin1["sequence"]
	+ rtx.txin2["outpoint"]
	+ rtx.txin2["outpoint_index"]
	+ struct.pack("<B", (len(sigscript2) + 1))
	+ struct.pack("<B", len(signature2) + 1)
	+ sigscript2
	+ rtx.txin2["sequence"]
	+ rtx.tx_out_count
	+ rtx.tx_out2["value"]
	+ rtx.tx_out2["pk_script_bytes"]
	+ rtx.tx_out2["script"]
	+ rtx.lock_time
	
)			#yay!

print real_tx.encode("hex")
