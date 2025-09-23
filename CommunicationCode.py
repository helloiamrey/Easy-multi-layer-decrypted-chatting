#import mmh3
import hashlib
from LoadAES import AESInterface
from EncodeJson import read_from_json, write_to_json
from SafeRand import generate_and_save_for_aes_seed


#PRIME_NUM = 1000003
#data = read_from_json('rand.json')
#a = read_from_json('UserList.json')


def return_hash_code(ip):
    """global a,data
    hash_with_seed = mmh3.hash(str(ip), seed=data['rand_num'])
    #MurmurHash3
    place_in_list = hash_with_seed % PRIME_NUM

    #Find an empty place in the list
    i=0
    print("Looking for a place in the list starting from "+str(place_in_list))
    while a[(place_in_list+i) % PRIME_NUM] != ['NOT_IP',0]:
        i+=1
    print("Found an empty place in the list at "+str((place_in_list+i) % PRIME_NUM))
    

    place = (place_in_list+i) % PRIME_NUM
    """
    # Use SHA-256 to hash the IP address and port into a fixed-length code
    hash_object = hashlib.sha256()
    hash_object.update(str(ip).encode('utf-8'))
    return hash_object.hexdigest()

    """
    a[place] = ip
    #The actual place in list
    aes_interface = AESInterface(data['rand_str'])
    ciphertext = aes_interface.encrypt_string(str(place))
    print(f"generated a new user with IP address "+ip[0]+" and port "+str(ip[1])+" at place "+str(place)+" in the list, and encrypted it with AES: {ciphertext}")
    write_to_json('UserList.json', a)
    print(a[place])
    return ciphertext
    """

"""
def decrypt_code(code):
    aes_interface = AESInterface(data['rand_str'])
    decrypted = aes_interface.decrypt_string(code)
    ip_pairs_gotten = a[int(decrypted)]
    return ip_pairs_gotten

def clear_list():
    write_to_json('UserList.json', [('NOT_IP',0)]*PRIME_NUM)
    write_to_json('rand.json', generate_and_save_for_aes_seed())
"""



#clear_list()
#look_for_place_in_list(("163.99.0.1",6600))
#print(rand_dict)
#print(a[1111])