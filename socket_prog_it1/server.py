# server.py

import socket
import sys
import threading
import os
from glob import glob
from datetime import datetime
from time import localtime, gmtime
from calendar import timegm
import re

def smtp(c:socket.socket, addr):
    
    def helper(msg, c, valid_commands):
        help = {
            "HELO" : 'Initiates SMTP session. Parameters: "SERVER", hostname  [Case-Insensitive]',
            "MAIL" : "Usage: MAIL FROM: <Sender's email address>  [Case-Insensitive]",
            "RCPT" : "Usage: RCPT TO: <Recipient's email address>  [Case-Insensitive]",
            "DATA": "Initiates input sequence to type message body"
        }
        if len(msg.split()) > 1:
            if msg.upper().split()[1] in ["HELO", "EHLO"]:
                c.send(f'214 {msg.upper().split()[1]}: {help["HELO"]}'.encode())
            elif msg.upper().split()[1] in valid_commands:
                c.send(f'214 {msg.upper().split()[1]}: {help[msg.upper().split()[1]]}'.encode())
            else:
                c.send(f"501 Syntax error in parameters or arguments: {msg}".encode())
        else:
            help_msg = "\n214 Help Message\n"\
                f'HELO / EHLO :\t{help["HELO"]}\n'\
                f'MAIL FROM :\t{help["MAIL"]}\n'\
                f'RCPT TO :\t{help["RCPT"]}\n'\
                f'DATA :\t{help["DATA"]}\n\n'
            c.send(
                help_msg.encode()
            )
    
    
    def data_input(msg, c, valid_commands):
        c.send(f'354 Enter message, ending with "." in a line by itself [Date is added in the server]'.encode())
        msg = c.recv(4096).decode()
        data = msg
        c.send("250 Requested mail action completed".encode())
        return data, msg
    
    def rcpt_to(msg, c, valid_commands):
        t = None
        data = None
        if len(msg.split(':')) > 1:
            to = msg.split(':')[1].strip().strip('<').strip('>')
            if '@' in to and not re.search(r'[\\/*?:"<>|]', to):
                if to.split('@')[1] == "447.edu":
                    c.send(f"250 Accepted".encode())
                    t = to
                    while True:
                        msg = c.recv(1024).decode()
                        msg_parts = msg.split()
                        if msg.upper() == "DATA":
                            data, msg = data_input(msg, c, valid_commands)
                            break
                        elif msg_parts[0].upper() in valid_commands:
                            c.send(f"503 Bad sequence of commands: {msg}".encode())
                            break
                        elif msg.upper().startswith("HELP"):
                            helper(msg, c, valid_commands) # help message function
                        elif msg_parts[0].upper() == "QUIT":
                            break
                        else:
                            c.send(f"500 Command unrecognised: {msg}".encode())
                            break
                else:
                    c.send(f"550 Mailbox unavailable from domain: {to.split('@')[1]}".encode())
            else:
                c.send(f"501 Syntax error in parameters or arguments: {msg}".encode())
        else:
            c.send(f"501 Syntax error in parameters or arguments: {msg}".encode())
        return t, data, msg
    
    def mail_from(msg, c, valid_commands):
        f = None
        t = None
        data = None
        if len(msg.split(':')) > 1:
            fro = msg.split(':')[1].strip().strip('<').strip('>')
            if '@' in fro and not re.search(r'[\\/*?:"<>|]', fro):
                if fro.split('@')[1] == "447.edu":
                    c.send(f"250 Accepted".encode())
                    f = fro
                    while True:
                        msg = c.recv(1024).decode().lower()
                        msg_parts = msg.split()
                        if msg.upper().split(':')[0].strip() == "RCPT TO":
                            t, data, msg = rcpt_to(msg, c, valid_commands)
                            break
                        elif msg_parts[0].upper() in valid_commands:
                            c.send(f"503 Bad sequence of commands: {msg}".encode())
                            break
                        elif msg.upper().startswith("HELP"):
                            helper(msg, c, valid_commands) # help message function)   
                        elif msg_parts[0].upper() == "QUIT":
                            break
                        else:
                            c.send(f"500 Command unrecognised: {msg}".encode())
                            break
                else:   
                    c.send(f"550 Mailbox unavailable from domain: {fro.split('@')[1]}".encode())
            else:
                c.send(f"501 Syntax error in parameters or arguments: {msg}".encode())
        else:
            c.send(f"501 Syntax error in parameters or arguments: {msg}".encode())
        return f, t, data, msg
    
    def init(msg, c, valid_commands):
        f, t, data = None, None, None
        msg_parts = msg.split()
        if msg.upper().split(':')[0].strip() == "MAIL FROM":
            f, t, data, msg = mail_from(msg, c, valid_commands)
        elif msg_parts[0].upper() in valid_commands:
            c.send(f"503 Bad sequence of commands: {msg}".encode())
        elif msg.upper().startswith("HELP"):
            helper(msg, c, valid_commands) # help message function
            msg = c.recv(1024).decode()
            f, t, data, msg = init(msg, c, valid_commands)
        elif msg_parts[0].upper() == "QUIT":
            pass
        else:
            c.send(f"500 Command unrecognised: {msg}".encode())
        return f, t, data, msg
            
    
    print(f'{addr} has conencted to SMTP server')
    
    valid_commands = ["HELO", "EHLO", "MAIL", "RCPT", "DATA"]
  
    # print(c.recv(1024).decode())
    c.send(f"220 {socket.gethostname()}".encode())
    msg = ''
    try:
        while msg.upper()!="QUIT":
            msg = c.recv(1024).decode()
            msg_parts = msg.split()
            if msg_parts[0].upper() in ["EHLO", "HELO"] and len(msg_parts) > 1 and msg_parts[0].upper() != "QUIT":
                if msg_parts[1].lower() == "server" or msg_parts[1] in [socket.gethostname(), socket.gethostbyname(socket.gethostname())]:
                    c.send(f"250 Hello {socket.gethostname()} [{socket.gethostbyname(socket.gethostname())}], pleased to meet you".encode())
                    while msg.upper()!="QUIT":                  
                        msg = c.recv(1024).decode().lower()
                        f, t, data, msg = init(msg, c, valid_commands)
                        if f and t and data:
                            rcpt = t.split('@')[0]
                            if not os.path.exists(f'db/{rcpt}'):
                                os.mkdir(f'db/{rcpt}')
                            timestamp = datetime.now().strftime('%a, %b %d %Y %H:%M:%S')
                            output = f"Date:\t{timestamp} {int((timegm(localtime()) - timegm(gmtime()))/3600):03d}\n"
                            data = data.strip()
                            if data.lower().startswith('from') or data.lower().startswith('to') or data.lower().startswith('subject'):
                                pass
                            else:
                                output+='\n'
                            
                            output+= data
                            
                            email_list = glob(f"db/{rcpt}/*.email")
                            email_list = sorted(email_list)
                            if len(email_list) > 0:
                                new_file_name = len(email_list) + 1
                            else:
                                new_file_name = 1
                            with open(f"db/{rcpt}/{new_file_name:03d}.email", 'w') as fout:
                                fout.write(output)
                else:
                    c.send(f"501 Syntax error in parameters or arguments: {msg}".encode())
            elif msg.upper() == "QUIT":
                pass    
            elif msg.upper().startswith("HELP"):
                helper(msg, c, valid_commands) # help message function
                msg = c.recv(1024).decode()
                f, t, data, msg = init(msg, c, valid_commands)
            elif msg_parts[0].upper() in ["EHLO", "HELO"] and len(msg_parts) <= 1:
                c.send("504 Command parameter not implemented".encode())
            elif msg.upper().split(':')[0] in valid_commands:
                c.send("503 Polite people say HELO first".encode())
            else:
                c.send(f"500 Command unrecognised: {msg}".encode())
            
            
            if msg.upper() == "QUIT":
                c.send(f"421 {socket.gethostname()} Service closing transmission channel".encode())
                print(f"{addr} has disconnected")
    except Exception as e:
        print(e)

def tcp_email_server(tcp_port:int):
    try:
        if not os.path.exists("db"):
            os.mkdir('db')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', tcp_port))
        s.listen()
        print(f"{datetime.now().strftime('%a, %b %d %Y %H:%M:%S')} {int((timegm(localtime()) - timegm(gmtime()))/3600):03d} TCP Server is now waiting for client connections on ({socket.gethostbyname(socket.gethostname())})...")
        while True:
            c, addr = s.accept()
            threading.Thread(target=smtp, args=((c, addr))).start()
    except Exception as e:
        print(f"TCP Connection error: {e}")

         
def http_200_response_formatter(filename, i, count):
    """Build HTTP 200 Response"""
    header = f"HTTP/1.1 200 OK\n"\
            f"Server: {socket.gethostbyname(socket.gethostname())}\n"\
            f"Last-Modified: {datetime.now().strftime('%a, %b %d %Y %H:%M:%S')} {int((timegm(localtime()) - timegm(gmtime()))/3600):03d}\n"\
            f"Count: {count}\n"\
            f"Content-Type: text/plain\n"\
            f"Message: {i}\n\n"
    with open(filename, 'r') as fin:
        body = fin.read()
    return header+body
        
    
def udp_http_server(udp_port:int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = ('', udp_port)
    s.bind(server_addr)
    print(f"{datetime.now().strftime('%a, %b %d %Y %H:%M:%S')} {int((timegm(localtime()) - timegm(gmtime()))/3600):03d} UDP Server is now waiting for client requests on ({socket.gethostbyname(socket.gethostname())})...")
    while True:
        request, addr = s.recvfrom(1024)
        print(f"Request from: {addr}")
        print(request.decode())
        request = request.decode().splitlines()
        buffer = []
        if len(request) >= 3:
            dest_user_name = request[0].split()[1]
            if os.path.exists(dest_user_name.strip('/')):
                emails = glob(f"{dest_user_name.strip('/')}/*.email")
                emails = sorted(emails, reverse=True)
                num_emails_req = int(request[2].strip("Count:"))
                if len(emails) >= num_emails_req: # check if count is valid
                    emails_to_send = emails[0:num_emails_req+1]
                    s.sendto("200 OK".encode(), addr)
                    for i in range(0, num_emails_req):
                        buffer.append(http_200_response_formatter(emails_to_send[i], i+1, num_emails_req))
                else:
                    s.sendto(f"200 OK: {len(emails)} emails available".encode(), addr)
                    for i in range(0, len(emails)):
                        buffer.append(http_200_response_formatter(emails[i], i+1, len(emails)))
                s.sendto(f"\n{'-'*60}\n".join(buffer).encode(), addr)
            else:
                s.sendto("404 Not Found".encode(), addr)
        else:
            s.sendto("400 Bad Request".encode(), addr)


    
if __name__ == "__main__":
    try:
        TCP_PORT = int(sys.argv[1])
        UDP_PORT = int(sys.argv[2])
    except IndexError:
        print("Required args have not been provided (hostname and port)")
    
    threading.Thread(target=tcp_email_server, args=[TCP_PORT]).start() # smtp thread tree

    threading.Thread(target=udp_http_server, args=[UDP_PORT]).start() # udp thread tree