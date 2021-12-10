###########################################################
#                    Authors:
#       1. Rahul Kumar Gupta - 1815125
#       2. Arvinder Singh - 1815126
#       3. Nilam Kumar Kalita – 1815127
#       4. Pritam Das - 1815128
#       5. Abhishek Kumar Jha – 1815134
###########################################################

import random
import hashlib
from Crypto.PublicKey import DSA

def create_DSA_key():
    key = DSA.generate(2048)
    f = open("./key.pem", "wb")
    f.write(key.exportKey())
    f.close()

def verify(e1, S2, p, e2, S1, message):
    # Verifying (Signature verification)
    x_dash = (pow(e1, S2, p) * pow(e2, -(int(S1, 16)), p)) % p

    received_message = message
    message_dash = received_message + str(x_dash)
    digest_dash = hashlib.sha256(message_dash.encode())
    S1_dash = digest_dash.hexdigest()
    if(S1==S1_dash):
        return True
    else:
        return False

def schnorr_digital_signature():
    f = open("key.pem", "rb") # File opened in read byte mode
    key = DSA.import_key(f.read()) # Key is read

    # Secure p and q
    p = key.p
    q = key.q
    assert ((p-1)%q==0) # Assertion for pre-condition

    # Parameters calculated as per Schnorr equations and asserted
    exponent = int(p-1)//int(q)
    e0 = p-2
    e1 = pow(e0,exponent,p)
    assert (e1!=1)
    val = pow(e1,q,p)
    assert (val==1)

    # private key
    d = random.randint(1,q-1)
    # public key
    e2 = pow(e1,d,p)

    # Alice's public key: (e1,e2,p,q) , private key: d

    # Signing (Signature generation)
    r = random.randint(1,q-1) # random number generation as per range
    x = pow(e1,r,p) # part to append to the message

    orig_message = "schnorrdigitalsignature" # Original Message
    message = orig_message+str(x) # Message after appending

    # SHA digest
    digest = hashlib.sha256(message.encode()) # digest generation
    S1 = digest.hexdigest() # digest retrieval
    S2 = (r+(d*int(S1,16)))%q # calculating other part of the signature

    # Verification
    received_message = "schnorrdigitalsignature9122" # Received message
    is_verified = verify(e1, S2, p, e2, S1, received_message) # verification after passing parameters to verify function

    if(is_verified==True):
        print("Signature Verified!")
    else:
        print("Signature Invalid!")


def check_key():
    f = open("key.pem", "rb")
    key = DSA.import_key(f.read())
    print(key)


if __name__ == '__main__':
    # create_DSA_key()
    schnorr_digital_signature()
    # find()