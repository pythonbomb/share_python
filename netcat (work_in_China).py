import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr=subprocess.STDOUT, shell=True)
    return output.decode(encoding='gb2312', errors='ignore')

class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()
    
    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.buffer += b'\n'
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode(encoding='gb2312', errors='ignore')
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('>>>')
                    buffer += '\n'
                    self.socket.send(buffer.encode(encoding='gb2312', errors='ignore'))
        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()


    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            try:
                client_socket, _ = self.socket.accept()
                client_thread = threading.Thread(
                    target=self.handle, args=(client_socket,)
                )
                client_thread.start()            
            except OSError as e:
                print(f'OSError:{e}')
                sys.exit(0)
            
        
            
    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode(encoding='gb2312', errors='ignore'))

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                data = data.decode(encoding='gb2312', errors='ignore').replace('\n', '')
                if not data:
                    client_socket.send(b'[*] Stop Upload.')
                    break
                client_socket.send(b'[*] Uploading...')
                file_buffer += data.encode(encoding='gb2312', errors='ignore')
                    
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
                f.close()
            message = f'[*] Saved file {self.args.upload}'
            client_socket.send(message.encode(encoding='gb2312', errors='ignore'))

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode(encoding='gb2312', errors='ignore'))
                    if response:
                        client_socket.send(response.encode(encoding='gb2312', errors='ignore'))
                    else:
                        client_socket.send('okay.'.encode(encoding='gb2312', errors='ignore'))
                    cmd_buffer = b''
                except Exception as e:
                    print(f'\n[*] Server killed ({e})')
                    self.socket.close()
                    sys.exit()
                    
                    
class Proxy:
    def __init__(self, local_host, local_port, remote_host, remote_port, receive_first=False):
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.receive_first = receive_first
        self.remote_buffer = ''
        self.local_buffer = ''
        self.HEX_FILTER = ''.join([(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])
        
    def hexdump(self, src, length=16, show=True):
        if isinstance(src, bytes):
            src = src.decode()
                
        results = list()
        for i in range(0, len(src), length):
            word = str(src[i:i+length])
            printable = word.translate(self.HEX_FILTER)
            hexa = ''.join([f'{ord(c):02X}' for c in word])
            hexwidth = length*3
            results.append(f'{i:04X}  {hexa:<{hexwidth}}  {printable}')
        if show:
            for line in results:
                print(line)
        else:
            return results    
    
    def receive_from(self, connection):
        connection.settimeout(5)
        buffer = b''
        try:
            while True:
                data = connection.recv(4096)
                if not len(data):
                    break
                buffer += data
        except Exception:
            pass
        if buffer:
            return buffer
        else:
            print('[!] No Reply.')
            return b''
    
    def request_handler(self, buffer):  
        # Do Something You Want
        return buffer
    
    def response_handler(self, buffer):  
        # Do Something You Want
        return buffer    
        
    def proxy_handler(self, client_socket):
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((self.remote_host, self.remote_port))
        
        if self.receive_first:
            self.remote_buffer = self.receive_from(remote_socket)
            self.hexdump(self.remote_buffer)
            
            remote_buffer = self.response_handler(self.remote_buffer)
            if len(remote_buffer):
                print('[<==] Sending %d bytes to localhost.' % len(remote_buffer))
                client_socket.send(remote_buffer)
        
        while True:
            self.local_buffer = self.receive_from(client_socket)
            if len(self.local_buffer):
                print('[==>] Received %d bytes from localhost.' % len(self.local_buffer))
                self.hexdump(self.local_buffer)
                local_buffer = self.request_handler(self.local_buffer)
                remote_socket.send(local_buffer)
                print('[==>] Sent to remote.')
            
            self.remote_buffer = self.receive_from(remote_socket)
            if len(self.remote_buffer):
                print('[<==] Received %d bytes from remote.' % len(self.remote_buffer))
                self.hexdump(self.remote_buffer)
                
                remote_buffer = self.response_handler(self.remote_buffer)
                client_socket.send(remote_buffer)
                print('[<==] Sent to localhost.')
                
            if not len(self.local_buffer) or not len(self.remote_buffer):
                client_socket.close()
                remote_socket.close()
                print('[*] No more data. Closing connections.')
                break
        
    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((self.local_host, self.local_port))
        except Exception as e:
            print('problem on bind: %r' % e)
            print('[!!] Failed to listen on %s:%d' % (self.local_host, self.local_port))
            print('[!!] Check for other listening sockets or correct permissions.')
            sys.exit(0)
        print("[*] Listening on %s:%d" % (self.local_host, self.local_port))
        server.listen(5)
        while True:
            client_socket, addr =  server.accept()
            print('> Received incoming connection from %s:%d' % (addr[0], addr[1]))
            proxy_thread = threading.Thread(
                target=self.proxy_handler,
                args=(client_socket,
                ))
            proxy_thread.start()



        
        
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Fishcan Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
            netcat.py -t 192.168.31.25 -p 5555 -l -c # command shell
            netcat.py -t 192.168.31.25 -p 5555 -l -u=mytext.txt # upload file
            netcat.py -t 192.168.31.25 -p 5555 -l -e=\"cat/etc/passwd\" # execute command
            echo 'ABC' | ./netcat.py  -t 192.168.31.25 -p 5555 # echo text to server port 5555
            netcat.py -t 192.168.31.25 -p 5555 # connect to server
            netcat.py -py -lh 8.8.8.8 -lp 10000 -rh 9.9.9.9 -rp 10000 # create proxy
            # If the remote host want to send data first, use '-rf'.
        '''))
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default='5555', help='specified port')
    parser.add_argument('-t', '--target', default='192.168.31.25', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    parser.add_argument('-py', '--proxy', action='store_true', help='create proxy')
    parser.add_argument('-lh', '--local_host', type=str, help='specified local host')
    parser.add_argument('-lp', '--local_port', type=int, help='specified local port')
    parser.add_argument('-rh', '--remote_host', type=str,  help='specified remote host')
    parser.add_argument('-rp', '--remote_port', type=int, help='specified remote port')
    parser.add_argument('-rf', '--receive_first', action='store_true', help='if receive first')    
    args = parser.parse_args()
    if args.proxy:
        if (args.local_host == None or args.local_port == None or args.remote_host == None or args.remote_port) == None:
            parser.print_help()
            print('\n[!] Lost argument.')
            sys.exit(0)
        if args.receive_first:
            rf = True
        else:
            rf = False
        p = Proxy(args.local_host, args.local_port, args.remote_host, args.remote_port, receive_first=rf)
        p.run()
    elif not args.proxy:
        if args.listen:
            buffer = ''
        else:
            buffer = input('>>>')
        
        nc = NetCat(args, buffer.encode())
        nc.run()
    
    
        
        
