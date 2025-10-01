import socket
import ssl
import threading
import hashlib
from sm2_ecc_server import encrypt_data, decrypt_data, generate_keypair
from CommunicationCode import return_hash_code
from threading import Condition

sha256_condition = Condition()
chat_condition = Condition()
sha256list=[]
chatlist=[]

class server_ssl:

    def build_listen(self):
        CA_FILE = "cert/ca-cert.pem"
        KEY_FILE = "cert/server-key.pem"
        CERT_FILE = "cert/server-cert.pem"
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED  # 如果服务器不验证客户端证书：ssl.CERT_NONE 
        #context.check_hostname = False

        # 监听端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            # 将socket打包成SSL socket
            with context.wrap_socket(sock, server_side=True) as ssock:
                ssock.bind(('0.0.0.0', 9443))
                ssock.listen(5)
                print("Server is listening for connections...")
                
                while True:
                    try:
                        # 接收客户端连接
                        ssock.settimeout(1.0)
                        client_socket, addr = ssock.accept()
                        print(f"Accepted connection from {addr}")

                        # 创建新线程来处理客户端请求
                        client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr),daemon=True)
                        client_thread.start()
                    except socket.timeout:
                        continue


    def handle_client(self, client_socket, addr):
        global sha256list,chatlist
        client_socket.settimeout(5.0) #超时时间
            # 生成密钥对
        keypair=generate_keypair()

        # 发送公钥给客户端
        print(f"Generated keypair for client {addr}: Private Key: {keypair[0]}, Public Key: {keypair[1]}")
        client_socket.send(f"Public Key: {keypair[1]}".encode("utf-8"))
        # 接收客户端公钥
        client_pub_key = client_socket.recv(1024).decode("utf-8")
        # 测试通讯
        if not client_pub_key:
            raise ValueError("Client public key is None")
        print(f"Received public key from client {addr}: {client_pub_key}")

        code=return_hash_code(addr)
        print(f"Assigned code to client {addr}: {code}")
        msg=f"\nHello from server.Here are some tips: \n - Enter 'chat-<YOUR_CODE>' to connect to a specific host with a known communication-code for multi-layer encrypted communication. \n   For example,'chat-abcdefg12345'. Space is not added.\n - Enter 'exit' to exit. \n - Your communication code is {code}. \n - All messages you send will be sent back as a notice to confirm that the information is correct before it is processed.\n - The server may be closed if it doesn't make response for a few minutes.\nHave fun chatting anonymously."
        client_socket.send(encrypt_data(msg, None, client_pub_key).encode("utf-8"))



        client_socket.settimeout(300)
        while True:
            try:
                print("test.")
                if not any(item[0] == code for item in sha256list):
                    client_socket.settimeout(5.0)
                # 与客户端通信
                    # 接收客户端信息
                    msg = client_socket.recv(1024).decode("utf-8")
                    #if not msg:
                    #    break  # 客户端断开连接
                    msg=decrypt_data(msg, keypair[0], keypair[1])
                    print(f"Received message from client {addr}: {msg}")

                    # 向客户端发送信息
                    #response = encrypt_data(f"Server has recieved: {msg}", None, client_pub_key).encode("utf-8")
                    #client_socket.send(response)

                    #主要判断在这里添加功能    
                    if msg=="exit":
                        client_socket.send(encrypt_data("Goodbye.", None, client_pub_key).encode("utf-8"))
                        break
                    elif "chat" in msg:
                        print("Loading chat connection...")
                        client_sended_code = msg[5:]
                        print(f"Client is trying to connect to code <{client_sended_code}>.")
                        sha256list.append((client_sended_code, code))
                        client_socket.send(encrypt_data(f"You are connecting to user with code <{client_sended_code}>.", None, client_pub_key).encode("utf-8"))
                        #连接
                        #while next((i for i, t in enumerate(chatlist) if t[1] == code), -1)==-1:
                        #    pass
                        with sha256_condition:
                            while any(t[1] == code for t in sha256list):
                                sha256_condition.wait(timeout=10)
                        
                        print("Connection established. Starting multi-layer encrypted communication...")
                        client_socket.send(encrypt_data("Connection established. You can start chatting now. Enter 'exit' to exit the chat.", None, client_pub_key).encode("utf-8"))
                        while True:
                            while True:
                                first_msg_index = next((i for i, t in enumerate(chatlist) if t[1]==code), None)
                                if first_msg_index != None:
                                    if chatlist[first_msg_index][0]=="exit":
                                        client_socket.send(encrypt_data("The other party closed the connection.", None, client_pub_key).encode("utf-8"))
                                        break
                                    client_socket.send(encrypt_data(f"[MESSAGE]<{chatlist[first_msg_index][1]}>:[{chatlist[first_msg_index][0]}]", None, client_pub_key).encode("utf-8"))
                                    chatlist.pop(first_msg_index)
                                else:
                                    break

                            msg=decrypt_data(client_socket.recv(1024).decode("utf-8"), keypair[0], keypair[1])
                            with chat_condition:
                                chatlist.append((msg, client_sended_code))
                                chat_condition.notify_all()
                            if msg=="exit":
                                print("Client exited the multi-layer encrypted chat.")
                                client_socket.send(encrypt_data("Goodbye.", None, client_pub_key).encode("utf-8"))
                                break

                    else:
                        print("Client sent an unknown command.")
                        client_socket.send(encrypt_data("Unknown command. Please try again.", None, client_pub_key).encode("utf-8"))
                    
                else:
                    try:
                        client_socket.settimeout(120)
                        client_socket.send(encrypt_data("A user is connecting to you. Input his/her code to verify the connection.", None, client_pub_key).encode("utf-8"))
                        msg = client_socket.recv(1024).decode("utf-8")
                        msg=decrypt_data(msg, keypair[0], keypair[1])
                        actual_code=next((item[1] for item in sha256list if item[0] == code), None)
                        res=True
                        if len(msg)==len(actual_code):
                            res=True
                            for i in range(len(msg)):
                                res= res&(msg[i]==actual_code[i])
                                #verify code

                        if res:
                            #start chatting
                            #print("Code verified. Starting multi-layer encrypted communication...")
                            client_socket.send(encrypt_data("Code verified.", None, client_pub_key).encode("utf-8"))
                            client_socket.settimeout(300)
                            with sha256_condition:
                                sha256list.remove((code, actual_code))
                                sha256_condition.notify_all()

                            while True:
                                with chat_condition:
                                    while not any(t[1] == code for t in chatlist):
                                        chat_condition.wait(timeout=30)
                                    first_msg_index = next((i for i, t in enumerate(chatlist) if t[1]==code), None)
                                    if first_msg_index != None:
                                        if chatlist[first_msg_index][0]=="exit":
                                            client_socket.send(encrypt_data("The other party closed the connection.", None, client_pub_key).encode("utf-8"))
                                            break
                                        client_socket.send(encrypt_data(f"[MESSAGE]<{actual_code}>:[{chatlist[first_msg_index][0]}]", None, client_pub_key).encode("utf-8"))
                                        chatlist.pop(first_msg_index)
                                    else:
                                        break
                                msg=decrypt_data(client_socket.recv(1024).decode("utf-8"), keypair[0], keypair[1])
                                with chat_condition:
                                    chatlist.append((msg, actual_code))
                                    chat_condition.notify_all()
                                if msg=="exit":
                                    client_socket.send(encrypt_data("Goodbye.", None, client_pub_key).encode("utf-8"))
                                    break
                        else:
                            client_socket.send(encrypt_data("Code incorrect. Connection closed.", None, client_pub_key).encode("utf-8"))
                            raise ValueError("Code incorrect.")

                                #ete chatting


                    except socket.timeout:
                        print("Client did not respond in time. Ending connection.")
                        client_socket.send(encrypt_data("Connction closed because of timeoutErr. Connect to server again to retry.", None, client_pub_key).encode("utf-8"))
                        break






            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error: {str(e)} in the connection {addr}")
                break

        client_socket.close()
        print("Connection closed")
        return 