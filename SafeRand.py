import secrets
import hashlib
def random_string_in_128_bytes():
    # 生成一个128字节的随机密钥
    token_bytes = secrets.token_bytes(128)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(token_bytes)
    encrypted_hash = sha256_hash.hexdigest()
    print("Successfully generated a new random key in 128 bytes and encrypted it with SHA-256: "+encrypted_hash)
    return encrypted_hash

def random_int_below(val):
    # 生成一个小于的随机数    
    if val <= 0:
        raise ValueError("输入必须大于0")
    randnum = secrets.randbelow(val)
    print(f"A random number below {val} is generated: "+str(randnum))
    return randnum

def random_int_within_interval(min_val, max_val):
    """
        min_val (int): 区间最小值（包含）
        max_val (int): 区间最大值（包含）

        return int: 在[min_val, max_val]范围内的随机整数
    """
    if min_val > max_val:
        raise ValueError("最小值不能大于最大值")
    
    # 计算区间范围大小
    range_size = max_val - min_val + 1
    ans=min_val + secrets.randbelow(range_size)
    # 生成随机偏移量并调整到目标区间
    print(f"A random number between {min_val} and {max_val} is generated: "+str(ans))
    return ans

def generate_and_save_for_aes_seed():
    rand_dict=rand_dict ={"rand_num": None, "rand_str": None}
    rand_num = random_int_below(1000000)
    rand_str = random_string_in_128_bytes()
    rand_dict = {'rand_num': rand_num, 'rand_str': rand_str}
    return rand_dict