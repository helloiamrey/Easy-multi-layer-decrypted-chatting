import socket
import ssl
from sm2_ecc_client import generate_keypair, encrypt_data, decrypt_data
import threading
import time

ifclosed = False
targetAddress,targetPort='',0

class client_ssl:
    def communication(self,pri_key=None,pub_key=None):
        global targetAddress,targetPort
        print(f"Client Keypair: Private Key: {pri_key}, Public Key: {pub_key}")
        try:
            CA_FILE = "cert/ca-cert.pem"
            SERVER_CERT_FILE = "cert/server-cert.pem"  # 服务器证书文件路径
            CLIENT_KEY_FILE = "cert/client-key.pem"
            CLIENT_CERT_FILE = "cert/client-cert.pem"
        except Exception as e:
            print(f"Error loading certificate files: {str(e)}, maybe cert missing?")
            return

        # 创建SSL上下文对象
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=CA_FILE)  # 设置根证书

        print("Client is starting...")
        try:
            # 与服务端建立socket连接
            sock = socket.socket()
            # 将socket打包成SSL socket
            ssock = context.wrap_socket(sock, server_side=False)
            ssock.settimeout(5.0)
            ssock.connect((targetAddress, int(targetPort)))
        except Exception as e:
            print(f"Failed to connect to server: {str(e)}")
            return
        print("Client connected to server.")

        # 接收服务器发送的公钥
        response = ssock.recv(1024).decode("utf-8")
        server_pub_key = response.split("Public Key: ")[1]
        print(f"Received public key from server: {server_pub_key}")
        # 发送客户端公钥给服务器
        if pub_key==None:
            raise ValueError("Public key is None")
        if pri_key==None:
            raise ValueError("Private key is None")
        ssock.send(pub_key.encode("utf-8"))

        def receive():
            global ifclosed
            ssock.settimeout(5.0)
            while True:
                try:
                    if ifclosed:
                        break
                    response = ssock.recv(1024).decode("utf-8")
                    if response:
                        response = decrypt_data(response, pri_key, pub_key)
                        print(f"Received message from the server: {response}")
                        if "Enter 'ete-<A PUBLIC KEY>'" in response:
                            print("\n<NOTICE> Input '##genkey' to generate a new keypair for end-to-end encryption and send the public key to the server automatically.")
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"\nAn error occurred while receiving data: {str(e)}")
                    ifclosed = True
                    break
        def send():
            time.sleep(1) #等待接收线程启动
            global ifclosed
            ssock.settimeout(5.0)
            while True:
                try:
                    message = input()
                    encrypted_message = encrypt_data(message, None, server_pub_key)
                    ssock.send(encrypted_message.encode("utf-8"))
                    if message.lower() == 'exit':
                        print("Exiting...")
                        time.sleep(2)
                        ifclosed = True
                        break
                    if message=="##genkey":
                        new_pairs=generate_keypair()
                        print(f"Generated new keypair: Private Key: {new_pairs[0]}, Public Key: {new_pairs[1]} and sending the public key to server.")
                        message = "##ete-" + new_pairs[1]
                        encrypted_message = encrypt_data(message, None, server_pub_key)
                        ssock.send(encrypted_message.encode("utf-8"))
                    elif "##" in message:
                        print("\n<NOTICE> Make sure the format is correct. '##' is invalid in normal chat messages.")

                except Exception as e:
                    print(f"\nAn error occurred while sending data: {str(e)}")
                    ifclosed = True
                    break

        try:
            sender = threading.Thread(target=send, daemon=True)
            receiver = threading.Thread(target=receive, daemon=True)
            receiver.start()
            sender.start()
            sender.join()
            receiver.join()
        except KeyboardInterrupt:
            print("Client is shutting down...")
        except Exception as e:
            if e==BrokenPipeError:
                print("Connection closed by server.")
        finally:
            ssock.close()
            print("Connection closed.")


if __name__ == "__main__":
    print("Press Enter some info to start the client...")
    targetAddress=input("Target server address: ")
    targetPort=input("Target server port: ")
    client = client_ssl()
    pairs=generate_keypair()
    client.communication(pairs[0],pairs[1])