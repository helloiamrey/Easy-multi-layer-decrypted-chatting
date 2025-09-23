import base64
import rsa
 
 
class RsaDemo:
    def __init__(self):
        self.pubkey, self.privkey = rsa.newkeys(512)   #生成公钥、私钥对象，密钥位数512
 
    def encrypt_str(self,test_str):
        """
        加密
        :param test_str: 需要进行加密的字符串
        :return: 返回加密后的str
        """
        new_str = test_str.encode("utf8")   #字符串转为utf8字节码
        crypt_str = rsa.encrypt(message=new_str, pub_key=self.pubkey)   #加密，之后数据类型为byte
        b64_str = base64.b64encode(crypt_str)  # base64编码，格式为byte
        result = b64_str.decode()    # 转为字符串
        print(type(result),result)
        return result
 
 
    def decrypt_str(self,crypt_str:str):
        """
        解密
        :param crypt_str:
        :return:
        """
        byte_str = crypt_str.encode()       #字符串编码为byte
        test_str = base64.b64decode(byte_str)          #base64解码
        byte_result = rsa.decrypt(crypto=test_str,priv_key=self.privkey)    #解密
        str_result = byte_result.decode()              #解码为字符串
        print(type(str_result), str_result)
 
 
if __name__ == '__main__':
    test = RsaDemo()
    phone = "13300000001"
    crypt_phone = test.encrypt_str(phone)
    decrypt_phone = test.decrypt_str(crypt_phone)