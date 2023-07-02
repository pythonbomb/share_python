import socket
import subprocess
import shlex
import sys
import ssh_cryptor
import getpass
import textwrap
import argparse

th = '192.168.31.51'
tp = 10000

def cmd(command):
    cmd = command.strip()
    if not cmd:
        return
    res = subprocess.check_output(shlex.split(cmd), stderr = subprocess.STDOUT, shell = True)
    return res.decode(encoding='gb2312', errors='ignore')



def receive_from(connection, timeout=100):
    connection.settimeout(timeout)
    recv_len = 1
    response = ''
    while recv_len:
        data = connection.recv(4096)
        recv_len = len(data)
        response += data.decode()
        if recv_len < 4096:
            break
    if response:
        return response
    
class SSH_client:
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
            data = ssh_cryptor.decrypt(response, type='cpri')
            return data.decode(encoding='gb2312', errors='ignore')
        
    def key(self):
        ssh_cryptor.generate(pub_name='cpub', pri_name='cpri')

    def main(self):
        self.key()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((th, tp))
        def login_and_account(socket):
            action = input('[*] Login or Create Account?  input:')
            if action == 'login' or 'account':
                a = f'{action}'
                socket.send(a.encode(encoding='gb2312'))
            else:
                print('[!] Action Wrong!')
                sys.exit(0)
            if action == 'login':
                pass
            elif action == 'account':
                key = socket.recv(4096)
                with open('key.serverkey', 'wb') as f:
                    f.write(key)
                    f.close()                    
                user = input('[*] User:')
                user_ = ssh_cryptor.encrypt(user.encode(encoding='gb2312'), type='serverkey')
                socket.send(user_)
                password = getpass.getpass()
                password_ = ssh_cryptor.encrypt(password.encode(encoding='gb2312'), type='serverkey')
                socket.send(password_)
                print('[*] Create Account Successfully.')
                print('[*] Now Continue Login ...')
            
        login_and_account(server)
            
        key = server.recv(4096)
        with open('key.serverkey', 'wb') as f:
            f.write(key)
            f.close()
        user = input('[*] User:')
        user_ = ssh_cryptor.encrypt(user.encode(encoding='gb2312'), type='serverkey')
        server.send(user_)

        password = getpass.getpass()

        password_ = ssh_cryptor.encrypt(password.encode(encoding='gb2312'), type='serverkey')
        server.send(password_)
        conn = receive_from(server)
        if conn == 'Connected':
            pass
        elif conn == 'Refuse':
            server.close()
            print('[!] Password May Wrong. Please Check Password.')
            print('[!] Or Check Whether Create Account Or Not.')
            sys.exit(0)
        
        with open('key.cpub', 'rb') as f:
            key = f.read()
            f.close()
        server.send(key)

        while True:
            buffer = ''
            while buffer == '' :
                buffer = input('Command:')
            if buffer == 'exit':
                server.send(ssh_cryptor.encrypt(buffer.encode(), type='serverkey'))
                print(f'[*] Client Exit.')                                    
                server.close()
                break
            server.send(ssh_cryptor.encrypt(buffer.encode(), type='serverkey'))
            request = self.receive_from(server)
            print(f'[*] Output: {request}')
    

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
    tp = arg.target
    tp = arg.port    
    a = SSH_client()
    a.main()