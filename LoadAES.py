from aes import AES

class AESInterface:
    def __init__(self, master_key):
        """初始化AES接口
        :param master_key: 16字节（128位）的十六进制字符串或整数密钥
        """
        if isinstance(master_key, str):
            # 将十六进制字符串转换为整数
            self.master_key = int(master_key, 16)
        else:
            self.master_key = master_key
        self.aes = AES(self.master_key)
    
    def encrypt_string(self, plaintext):
        """字符串加密
        :param plaintext: 明文字符串
        :return: 十六进制密文字符串
        """
        # 将字符串转换为字节（UTF-8编码）
        data = plaintext.encode('utf-8')
        
        # PKCS#7填充
        pad_len = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_len] * pad_len)
        
        # 分组加密
        ciphertext = b''
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            # 将字节块转换为整数（大端序）
            block_int = int.from_bytes(block, byteorder='big')
            # 加密
            encrypted_int = self.aes.encrypt(block_int)
            # 将加密后的整数转换回字节
            encrypted_block = encrypted_int.to_bytes(16, byteorder='big')
            ciphertext += encrypted_block
        
        # 转换为十六进制字符串
        return ciphertext.hex()
    
    def decrypt_string(self, ciphertext_hex):
        """字符串解密
        :param ciphertext_hex: 十六进制密文字符串
        :return: 明文字符串
        """
        # 将十六进制字符串转换为字节
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # 分组解密
        decrypted_data = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            # 将字节块转换为整数（大端序）
            block_int = int.from_bytes(block, byteorder='big')
            # 解密
            decrypted_int = self.aes.decrypt(block_int)
            # 将解密后的整数转换回字节
            decrypted_block = decrypted_int.to_bytes(16, byteorder='big')
            decrypted_data += decrypted_block
        
        # 去除PKCS#7填充
        pad_len = decrypted_data[-1]
        if pad_len > 16:
            raise ValueError("无效的填充数据")
        # 验证填充字节是否正确
        if decrypted_data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("填充验证失败")
        decrypted_data = decrypted_data[:-pad_len]
        
        # 将字节转换为字符串（UTF-8解码）
        return decrypted_data.decode('utf-8')
""""
    # 初始化接口
    aes_interface = AESInterface("2b7e151628aed2a6abf7158809cf4f3c")
    
    # 加密
    plaintext = "这sjsjndjjdjjxjdjsjsjsjsnwjajnsnzjsi"
    ciphertext = aes_interface.encrypt_string(plaintext)
    print(f"加密结果: {ciphertext}")
    
    # 解密
    decrypted_text = aes_interface.decrypt_string(ciphertext)
    print(f"解密结果: {decrypted_text}")
"""