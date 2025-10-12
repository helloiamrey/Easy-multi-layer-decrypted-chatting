import socket
import ssl
import threading
import hashlib
from sm2_ecc_server import encrypt_data, decrypt_data, generate_keypair
from CommunicationCode import return_hash_code
from threading import Condition
import re

sha256_condition = Condition()
chat_condition = Condition()
sha256list = []
chatlist = []

class server_ssl:

    def build_listen(self):
        CA_FILE = "cert/ca-cert.pem"
        KEY_FILE = "cert/server-key.pem"
        CERT_FILE = "cert/server-cert.pem"
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED  # 验证客户端证书
        
        # 监听端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            with context.wrap_socket(sock, server_side=True) as ssock:
                ssock.bind(('0.0.0.0', 9443))
                ssock.listen(5)
                print("Server is listening for connections...")
                
                while True:
                    try:
                        ssock.settimeout(1.0)
                        client_socket, addr = ssock.accept()
                        print(f"Accepted connection from {addr}")

                        client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                        client_thread.start()
                    except socket.timeout:
                        continue

    def handle_client(self, client_socket, addr):
        global sha256list, chatlist
        client_socket.settimeout(5.0)
        
        # 生成密钥对
        keypair = generate_keypair()

        # 发送公钥给客户端
        print(f"Generated keypair for client {addr}")
        client_socket.send(f"Public Key: {keypair[1]}".encode("utf-8"))
        
        # 接收客户端公钥
        client_pub_key = client_socket.recv(1024).decode("utf-8")
        if not client_pub_key :
            print(f"Invalid public key from {addr}: {client_pub_key}")
            client_socket.close()
            return
        
        print(f"Received public key from client {addr}")

        code = return_hash_code(addr)
        print(f"Assigned code to client {addr}: {code}")
        msg = f"\nHello from server.Here are some tips: \n - Enter 'chat-<CODE>' to connect to a specific user \n - Enter 'exit' to exit \n - Your communication code is {code} \n - All messages are encrypted"
        client_socket.send(encrypt_data(msg, None, client_pub_key).encode("utf-8"))

        client_socket.settimeout(300)
        is_chatting = False
        partner_code = None
        exit_flag = False
        # 新增验证状态变量
        waiting_for_verification = False
        verification_partner = None

        def receive_messages():
            nonlocal is_chatting, partner_code, exit_flag, waiting_for_verification, verification_partner
            
            while not exit_flag:
                try:
                    msg = client_socket.recv(1024).decode("utf-8")
                    if not msg:
                        break
                    
                    decrypted_msg = decrypt_data(msg, keypair[0], keypair[1])
                    print(f"Received from {addr}: {decrypted_msg}")

                    if decrypted_msg == "exit":
                        exit_flag = True
                        with chat_condition:
                            if partner_code:
                                chatlist.append(("exit", partner_code))
                                chat_condition.notify_all()
                        client_socket.send(encrypt_data("Goodbye.", None, client_pub_key).encode("utf-8"))
                        break
                    
                    # 处理验证响应
                    elif waiting_for_verification and verification_partner:
                        # 安全比较验证代码
                        if decrypted_msg == verification_partner:
                            # 验证成功
                            with sha256_condition:
                                # 清除相关的连接请求
                                sha256list[:] = [(c, p) for c, p in sha256list 
                                               if not (c == code and p == verification_partner)]
                                sha256_condition.notify_all()
                            
                            is_chatting = True
                            partner_code = verification_partner
                            waiting_for_verification = False
                            verification_partner = None
                            client_socket.send(encrypt_data("Verification successful. You can start chatting now.", 
                                                          None, client_pub_key).encode("utf-8"))
                        else:
                            # 验证失败
                            waiting_for_verification = False
                            verification_partner = None
                            client_socket.send(encrypt_data("Verification failed. Connection request rejected.", 
                                                          None, client_pub_key).encode("utf-8"))
                    
                    elif decrypted_msg.startswith("chat-") and not is_chatting:
                        client_sended_code = decrypted_msg[5:].strip()
                        # 验证代码格式安全性
                        if not self.is_valid_code(client_sended_code):
                            client_socket.send(encrypt_data("Invalid code format.", None, client_pub_key).encode("utf-8"))
                            continue
                            
                        print(f"Client {addr} trying to connect to {client_sended_code}")
                        with sha256_condition:
                            sha256list.append((client_sended_code, code))
                        client_socket.send(encrypt_data(f"Connecting to {client_sended_code}. Waiting for acceptance...", 
                                                      None, client_pub_key).encode("utf-8"))
                        
                        # 等待对方验证
                        with sha256_condition:
                            # 超时120秒
                            timeout = 120
                            while any(t[1] == code for t in sha256list) and timeout > 0 and not exit_flag:
                                sha256_condition.wait(1)
                                timeout -= 1
                            
                            if timeout <= 0 and any(t[1] == code for t in sha256list):
                                # 超时未验证
                                sha256list[:] = [(c, p) for c, p in sha256list if not (p == code)]
                                client_socket.send(encrypt_data("Connection request timed out.", 
                                                              None, client_pub_key).encode("utf-8"))
                            elif not exit_flag:
                                # 验证成功
                                is_chatting = True
                                partner_code = client_sended_code
                                client_socket.send(encrypt_data("Connection established. Start chatting.", 
                                                              None, client_pub_key).encode("utf-8"))
                    
                    elif is_chatting and partner_code:
                        with chat_condition:
                            chatlist.append((decrypted_msg, partner_code))
                            chat_condition.notify_all()
                        # 发送确认收到的消息
                        client_socket.send(encrypt_data("Message received.", None, client_pub_key).encode("utf-8"))
                    
                    else:
                        client_socket.send(encrypt_data("Unknown command. Try 'chat-<CODE>' or 'exit'", 
                                                      None, client_pub_key).encode("utf-8"))
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error receiving from {addr}: {e}")
                    exit_flag = True
                    break

        def send_messages():
            nonlocal is_chatting, partner_code, exit_flag, waiting_for_verification, verification_partner
            
            while not exit_flag:
                try:
                    if not is_chatting and not waiting_for_verification:
                        # 检查是否有新的连接请求
                        with sha256_condition:
                            # 查找针对当前客户端的连接请求
                            request = next((item for item in sha256list if item[0] == code), None)
                            if request:
                                requester_code = request[1]
                                # 标记为等待验证状态
                                waiting_for_verification = True
                                verification_partner = requester_code
                                
                                # 提示客户端输入验证代码
                                client_socket.send(encrypt_data(
                                    f"A user wants to connect. Enter their code to verify: {requester_code}", 
                                    None, client_pub_key).encode("utf-8"))
                    
                    elif is_chatting:
                        # 检查是否有来自聊天伙伴的消息
                        with chat_condition:
                            while not any(t[1] == code for t in chatlist) and not exit_flag:
                                chat_condition.wait(1)
                            
                            if exit_flag:
                                break
                            
                            # 获取并发送消息
                            first_msg_index = next((i for i, t in enumerate(chatlist) if t[1] == code), None)
                            if first_msg_index is not None:
                                msg_content, sender_code = chatlist.pop(first_msg_index)
                                if msg_content == "exit":
                                    client_socket.send(encrypt_data("The other party left the chat.", 
                                                                  None, client_pub_key).encode("utf-8"))
                                    exit_flag = True
                                    is_chatting = False
                                    partner_code = None
                                    break
                                client_socket.send(encrypt_data(f"[{sender_code}]: {msg_content}", 
                                                              None, client_pub_key).encode("utf-8"))
                
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error sending to {addr}: {e}")
                    exit_flag = True
                    break

        # 启动接收和发送线程
        receive_thread = threading.Thread(target=receive_messages, daemon=True)
        send_thread = threading.Thread(target=send_messages, daemon=True)
        
        receive_thread.start()
        send_thread.start()
        
        # 等待线程结束
        receive_thread.join()
        send_thread.join()
        
        # 清理资源
        print(f"Connection with {addr} closed.")
        # 清理残留的聊天信息
        with chat_condition:
            chatlist[:] = [(m, c) for m, c in chatlist if c != code and c != partner_code]
        
        with sha256_condition:
            sha256list[:] = [(c, p) for c, p in sha256list if c != code and p != code]
            
        client_socket.close()
    
    def is_valid_code(self, code):
        """验证代码格式安全性，防止注入攻击"""
        # 只包含字母数字和特定字符
        return bool(re.fullmatch(r'^[a-zA-Z0-9]{64}$', code))