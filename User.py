from certificateless_crypto import KGC, CLUser
kgc = KGC()
params = kgc.get_public_params()
kgc_pub_key_bytes = kgc.get_kgc_public_key_bytes()
# Step 2: Create two users (sender and receiver)
sender = CLUser("sender@example.com", params)
receiver = CLUser("receiver@example.com", params)
# Step 3: KGC provides partial private keys
sender_partial_key = kgc.extract_partial_private_key(sender.identity)
receiver_partial_key = kgc.extract_partial_private_key(receiver.identity)

sender.set_partial_private_key(sender_partial_key)
receiver.set_partial_private_key(receiver_partial_key)