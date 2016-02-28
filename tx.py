import struct
import ecdsa
import base58
import hashlib


outpoint = "9844f4682eae5bb14297a94124d09f7fd635dbb2241490c99ca2e2ec3dc821db"

Alice_adress 		= "1NWzVg38ggPoVGAG2VWt6ktdWMaV6S1pJK"
Alice_hashed_pubkey = base58.b58decode_check(Alice_adress)[1:].encode("hex")


Bob_adress	 		= "1ANRQ9bEJZcwXiw7YZ6uE5egrE7t9gCyip"
Bob_hashed_pubkey	= base58.b58decode_check(Bob_adress)[1:].encode("hex")


Alice_private_key	= "CF933A6C602069F1CBC85990DF087714D7E86DF0D0E48398B7D8953E1F03534A"

#############################################################################
class raw_tx:
	version 		= struct.pack("<L", 1)
	tx_in_count 	= 0		#temp
	tx_in 			= {}	#temp
	tx_out_count	= 0		#temp
	tx_out1		 	= {}	#temp
	tx_out2			= {}	#temp
	lock_time		= struct.pack("<L", 0)

	hash_code		= struct.pack("<L", 1)

	tx_to_sign 		= 0		#temp

	def flip_byte_order(self, string):  	#string, not bianry!
		flipped = "".join(reversed([string[i:i+2] for i in range(0, len(string), 2)]))
		return flipped


############################################################################

rtx = raw_tx()

rtx.tx_in_count 			= struct.pack("<B", 1)
rtx.tx_in["outpoint_hash"] 	= rtx.flip_byte_order(outpoint).decode("hex")
rtx.tx_in["outpoint_index"] = struct.pack("<L", 1)
rtx.tx_in["script_byes"] 	= 0		#temp
rtx.tx_in["script"] 		= ("76a914%s88ac" % Alice_hashed_pubkey).decode("hex")
rtx.tx_in["script_byes"] 	= struct.pack("<B", (len(rtx.tx_in["script"])))
rtx.tx_in["sequence"] 		= "ffffffff".decode("hex")




rtx.tx_out_count 				= struct.pack("<B", 2)

rtx.tx_out1["value"]			= struct.pack("<Q", 50000)		#send to Bob
rtx.tx_out1["pk_script_bytes"]	= 0			#temp
rtx.tx_out1["pk_script"]		= ("76a914%s88ac" % Bob_hashed_pubkey).decode("hex")
rtx.tx_out1["pk_script_bytes"]	= struct.pack("<B", (len(rtx.tx_out1["pk_script"])))




rtx.tx_out2["value"]			= struct.pack("<Q", 50000)		#send back (change)
rtx.tx_out2["pk_script_bytes"]	= 0			#temp
rtx.tx_out2["pk_script"]		= ("76a914%s88ac" % Alice_hashed_pubkey).decode("hex")
rtx.tx_out2["pk_script_bytes"]	= struct.pack("<B", (len(rtx.tx_out1["pk_script"])))


rtx.tx_to_sign = (
	rtx.version 
	+ rtx.tx_in_count 
	+ rtx.tx_in["outpoint_hash"] 
	+ rtx.tx_in["outpoint_index"] 
	+ rtx.tx_in["script_byes"] 
	+ rtx.tx_in["script"] 
	+ rtx.tx_in["sequence"]  
	+ rtx.tx_out_count 
	+ rtx.tx_out1["value"] 
	+ rtx.tx_out1["pk_script_bytes"] 
	+ rtx.tx_out1["pk_script"] 
	+ rtx.tx_out2["value"] 
	+ rtx.tx_out2["pk_script_bytes"] 
	+ rtx.tx_out2["pk_script"] 
	+ rtx.lock_time
	+ rtx.hash_code
	)


#############################################################################

hashed_raw_tx = hashlib.sha256(hashlib.sha256(rtx.tx_to_sign).digest()).digest()

#############################################################################

sk = ecdsa.SigningKey.from_string(Alice_private_key.decode("hex"), curve = ecdsa.SECP256k1)

vk = sk.verifying_key

public_key = ('\04' + vk.to_string()).encode("hex")
#############################################################################

sign = sk.sign_digest(hashed_raw_tx, sigencode=ecdsa.util.sigencode_der)

#############################################################################

sigscript = (
			sign 
			+ "\01" 
			+ struct.pack("<B", len(public_key.decode("hex"))) 
			+ public_key.decode("hex"))

#############################################################################

real_tx = (
	rtx.version 
	+ rtx.tx_in_count 
	+ rtx.tx_in["outpoint_hash"] 
	+ rtx.tx_in["outpoint_index"] 
	+ struct.pack("<B", (len(sigscript) + 1))
	+ struct.pack("<B", len(sign) + 1)	
	+ sigscript
	+ rtx.tx_in["sequence"]  
	+ rtx.tx_out_count 
	+ rtx.tx_out1["value"] 
	+ rtx.tx_out1["pk_script_bytes"] 
	+ rtx.tx_out1["pk_script"] 
	+ rtx.tx_out2["value"] 
	+ rtx.tx_out2["pk_script_bytes"] 
	+ rtx.tx_out2["pk_script"] 
	+ rtx.lock_time)

print real_tx.encode("hex")
