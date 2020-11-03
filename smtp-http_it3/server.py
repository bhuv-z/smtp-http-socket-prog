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
import json
from random import randint
import base64
import time
import ssl
import pprint
import hashlib

def create_log_file():
    fin = open(".server_log", "w")
    fin.close()

def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', str(pw+447).encode('utf-8'), salt, 100000)

def logger(frip, toip, command, msg):
    timestamp = f"{datetime.now().strftime('%a, %b %d %Y %H:%M:%S')} {int((timegm(localtime()) - timegm(gmtime()))/3600):03d}"
    if len(command) > 50:
        command = command[0:50] + "..."
    if len(msg) > 50:
        msg = msg[0:50] + "..."
    with open(".server_log", 'a') as log:
        log.write(f"{timestamp}\t{frip}\t{toip}\t{command}\t{msg}\n")
    
def smtp(c:socket.socket, addr):
    
    frohost = socket.gethostbyname(socket.gethostname())
    tohost, toport = c.getpeername()
    
    
    def helper(msg, c:socket.socket, valid_commands):
        command = "HELP"
        help = {
            "HELO" : 'Initiates SMTP session. Parameters: "SERVER", hostname  [Case-Insensitive]',
            "MAIL" : "Usage: MAIL FROM: <Sender's email address>  [Case-Insensitive]",
            "RCPT" : "Usage: RCPT TO: <Recipient's email address>  [Case-Insensitive]",
            "DATA": "Initiates input sequence to type message body",
            "AUTH": "Provide credentials after using this command to access the SMTP email service"
        }
        if len(msg.split()) > 1:
            if msg.upper().split()[1] in ["HELO", "EHLO"]:
                rep = f'214 {msg.upper().split()[1]}: {help["HELO"]}'
                c.send(rep.encode())
                logger(frohost, tohost, command, rep)
            elif msg.upper().split()[1] in valid_commands:
                rep = f'214 {msg.upper().split()[1]}: {help[msg.upper().split()[1]]}'
                c.send(rep.encode())
                logger(frohost, tohost, command, rep)
            else:
                rep = f"501 Syntax error in parameters or arguments: {msg}"
                c.send(rep.encode())
                logger(frohost, tohost, command, rep)
        else:
            help_msg = "\n214 Help Message\n"\
                f'HELO / EHLO :\t{help["HELO"]}\n'\
                f'AUTH :\t{help["AUTH"]}\n'\
                f'MAIL FROM :\t{help["MAIL"]}\n'\
                f'RCPT TO :\t{help["RCPT"]}\n'\
                f'DATA :\t{help["DATA"]}\n\n'
            c.send(
                help_msg.encode()
            )
            logger(frohost, tohost, command, help_msg)
    
    
    def data_input(msg, c, valid_commands):
        rep = f'354 Enter message, ending with "." in a line by itself [Date is added in the server]'
        c.send(rep.encode())
        logger(frohost, tohost, "DATA", rep)
        
        msg = c.recv(4096).decode()
        logger(frohost, tohost, "DATA", msg)
        
        data = msg
        
        rep = "250 Requested mail action completed"
        c.send(rep.encode())
        logger(frohost, tohost, "DATA", rep)
        
        return data, msg
    
    def domain_check(msg):
        return msg.split('@')[1] == "447.edu"
    
    def rcpt_to(msg, c, valid_commands):
        t = None
        data = None
        if len(msg.split(':')) > 1:
            to = msg.split(':')[1].strip().strip('<').strip('>').lower()
            if '@' in to and not re.search(r'[\\/*?:"<>|]', to):
                if domain_check(to):
                    rep = "250 Accepted"    
                    c.send(rep.encode())
                    logger(frohost, tohost, "RCPT TO", rep)
                    
                    t = to
                    while True:
                        rep = 'Enter "DATA" to begin writing the body of the email'
                        c.send(rep.encode())
                        logger(frohost, tohost, "DATA", rep)
                        
                        msg = c.recv(1024).decode()
                        logger(frohost, tohost, "DATA", msg)
                        
                        msg_parts = msg.split()
                        if msg.upper() == "DATA":
                            data, msg = data_input(msg, c, valid_commands)
                            break
                        elif msg_parts[0].upper() in valid_commands:
                            rep = f"503 Bad sequence of commands: {msg}"
                            c.send(rep.encode())
                            logger(frohost, tohost, msg, rep)
                            break
                        elif msg.upper().startswith("HELP"):
                            helper(msg, c, valid_commands) # help message function
                        elif msg_parts[0].upper() == "QUIT":
                            break
                        else:
                            rep = f"500 Command unrecognised: {msg}"
                            c.send(rep.encode())
                            logger(frohost, tohost, msg, rep)
                            break
                else:
                    rep = f"550 Mailbox unavailable from domain: {to.split('@')[1]}"
                    c.send(rep.encode())
                    logger(frohost, tohost, "RCPT TO", rep)
            else:
                rep = f"501 Syntax error in parameters or arguments: {msg}"
                c.send(rep.encode())
                logger(frohost, tohost, "RCPT TO", rep)
        else:
            rep = f"501 Syntax error in parameters or arguments: {msg}"
            c.send(rep.encode())
            logger(frohost, tohost, "RCPT TO", rep)
            
        return t, data, msg
    
    def mail_from(msg, c, valid_commands, user_name):
        f = None
        t = None
        data = None
        if len(msg.split(':')) > 1:
            fro = msg.split(':')[1].strip().strip('<').strip('>').lower()
            if '@' in fro and not re.search(r'[\\/*?:"<>|]', fro):
                if domain_check(fro) and user_name == fro:
                    rep = "250 Accepted"
                    c.send(rep.encode())
                    logger(frohost, tohost, "MAIL FROM", rep)

                    f = fro
                    while True:
                        c.send("RCPT TO [Only Enter Recipient's Email Address]: ".encode())
                        msg = c.recv(1024).decode().lower()
                        logger(frohost, tohost, "MAIL FROM", msg)
                        
                        if not msg.upper() == "QUIT" and not msg.upper().startswith("HELP"):
                            msg = "RCPT TO: " + msg
                        msg_parts = msg.split()
                        if msg.upper().split(':')[0].strip() == "RCPT TO":
                            t, data, msg = rcpt_to(msg, c, valid_commands)
                            break
                        elif msg_parts[0].upper() in valid_commands:
                            rep = f"503 Bad sequence of commands: {msg}"
                            c.send(rep.encode())
                            logger(frohost, tohost, msg, rep)
                            break
                        elif msg.upper().startswith("HELP"):
                            helper(msg, c, valid_commands) # help message function)   
                        elif msg_parts[0].upper() == "QUIT":
                            break
                        else:
                            rep = f"500 Command unrecognised: {msg}"
                            c.send(rep.encode())
                            logger(frohost, tohost, msg, rep)
                            break
                else:   
                    rep = f"550 Mailbox unavailable from domain, or email address does not match authenticated user: {fro}"
                    c.send(rep.encode())
                    logger(frohost, tohost, "MAIL FROM", rep)
            else:
                rep = f"501 Syntax error in parameters or arguments: {msg}"
                c.send(rep.encode())
                logger(frohost, tohost, "MAIL FROM", rep)
        else:
            rep = f"501 Syntax error in parameters or arguments: {msg}"
            c.send(rep.encode())
            logger(frohost, tohost, "MAIL FROM", rep)
            
        return f, t, data, msg


    def auth(msg, c, valid_commands, authorized):
        f, t, data = None, None, None
        rep = "334 dXNlcm5hbWU6"
        c.send(rep.encode())
        logger(frohost, tohost, "AUTH", rep)
        
        msg = c.recv(1024).decode()
        logger(frohost, tohost, "AUTH", msg)
        
        if os.path.exists("db/.user_pass"):
            with open('db/.user_pass', 'r') as fin:
                creds = json.loads(fin.read())
        else:
            creds = {}

        u_name = msg
        if u_name in creds:
            rep = "334 cGFzc3dvcmQ6"
            c.send(rep.encode())
            logger(frohost, tohost, "AUTH", rep)
            
            msg = c.recv(1024).decode()
            logger(frohost, tohost, "AUTH", msg)
            
            pw = base64.b64decode(msg).decode()
            pw = hash_pw(int(pw), bytes.fromhex(creds[u_name][1]))
            
            if bytes.fromhex(creds[u_name][0]) == pw:
                rep = "235 Authentication Succeeded"
                c.send(rep.encode())
                logger(frohost, tohost, "AUTH", rep)
                
                authorized = True
                
                rep = "MAIL FROM [Only Enter Your Email Address]: "
                c.send(rep.encode())
                logger(frohost, tohost, "AUTH", rep)
                
                msg = c.recv(1024).decode()
                logger(frohost, tohost, "AUTH", msg)
                
                if not msg.upper() == "QUIT" and not msg.upper().startswith("HELP"):
                    msg = "MAIL FROM: " + msg
                msg_parts = msg.split()
                if msg.upper().split(':')[0].strip() == "MAIL FROM":
                    f, t, data, msg = mail_from(msg, c, valid_commands, base64.b64decode(u_name).decode())
                elif msg_parts[0].upper() in valid_commands:
                    rep = f"503 Bad sequence of commands: {msg}"
                    c.send(rep.encode())
                    logger(frohost, tohost, msg, rep)
                elif msg.upper().startswith("HELP"):
                    helper(msg, c, valid_commands) # help message function
                    rep = "Enter QUIT to end email session\n[or send another email]\nMAIL FROM [Only Enter Email Address]: "
                    c.send(rep.encode())
                    logger(frohost, tohost, msg, rep)
                    
                    msg = c.recv(1024).decode()
                    logger(frohost, tohost, msg, '')
                    
                    if not msg.upper() == "QUIT" and not msg.upper().startswith("HELP"):
                        msg = "MAIL FROM: " + msg
                    f, t, data, msg, authorized, u_name = init(msg, c, valid_commands, authorized, u_name)
                elif msg_parts[0].upper() == "QUIT":
                    pass
                else:
                    rep = f"500 Command unrecognised: {msg}"
                    c.send(rep.encode())
                    logger(frohost, tohost, msg, rep)
            else:
                rep = "535 Authentication credentials are invalid - Resend AUTH command"
                c.send(rep.encode())
                logger(frohost, tohost, msg, rep)
        else:
            pw = randint(10000, 99999)
            rep = f"330 {pw}"
            c.send(rep.encode())
            logger(frohost, tohost, "AUTH", rep)
            salt = os.urandom(32)
            creds[msg] = (hash_pw(pw, salt).hex(), salt.hex())
            
            with open('db/.user_pass', 'w+') as file:
                json.dump(creds, file)
            msg = 'QUIT'
        
        return f, t, data, msg, authorized, u_name

    def init(msg, c, valid_commands, authorized, u_name=''):
        f, t, data = None, None, None
        msg_parts = msg.split()
        if not authorized and msg.upper().strip() == "AUTH":
            f, t, data, msg, authorized, u_name = auth(msg, c, valid_commands, authorized)
        elif authorized and msg.upper().split(':')[0].strip() == "MAIL FROM":
            f, t, data, msg = mail_from(msg, c, valid_commands, base64.b64decode(u_name).decode())
            authorized = True
        elif msg_parts[0].upper() in valid_commands:
            rep = f"503 Bad sequence of commands: {msg}"
            c.send(rep.encode())
            logger(frohost, tohost, msg, rep)
        elif msg.upper().startswith("HELP"):
            helper(msg, c, valid_commands) # help message function
            if authorized:
                rep = "Enter QUIT to end email session\n[or send another email]\nMAIL FROM [Only Enter Email Address]: "
                c.send(rep.encode())
                logger(frohost, tohost, msg, rep)
                
                msg = c.recv(1024).decode()
                logger(frohost, tohost, msg, '')
                
                if not msg.upper() == "QUIT" and not msg.upper().startswith("HELP"):
                    msg = "MAIL FROM: " + msg
            else:
                rep = "Send the AUTH Command, and enter your username and password for the prompts that follow. If you aren't already registered, a temporary password will be created."           
                c.send(rep.encode())
                logger(frohost, tohost, "AUTH", rep)
                
                msg = c.recv(1024).decode().lower()
                logger(frohost, tohost, msg, '')
                
            f, t, data, msg, authorized, u_name = init(msg, c, valid_commands, authorized, u_name)
            
        elif msg_parts[0].upper() == "QUIT":
            pass
        else:
            rep = f"500 Command unrecognised: {msg}"
            c.send(rep.encode())
            logger(frohost, tohost, msg, rep)
        return f, t, data, msg, authorized, u_name
    
    
    cons = f'{addr} has connected to SMTP server'
    print(cons)
    logger(frohost, tohost, cons, '')
    
    valid_commands = ["HELO", "EHLO", "MAIL", "RCPT", "DATA", "AUTH"]
  
    # print(c.recv(1024).decode())
    rep = f"220 {socket.gethostname()}"
    c.send(rep.encode())
    logger(frohost, tohost, rep, '')
    time.sleep(1) # rest a sec
    msg = ''
    try:
        authorized = False
        u_name = ''
        while msg.upper()!="QUIT":
            rep = "Use HELP or HELP <command_name> for information on the available SMTP commands\nUse QUIT to end SMTP session\n\nGreet the server with the commands: HELO server [OR] EHLO server"
            c.send(rep.encode())
            logger(frohost, tohost, "STARTUP", rep)
            
            msg = c.recv(1024).decode()
            logger(frohost, tohost, msg, '')
            
            msg_parts = msg.split()
            if msg_parts[0].upper() in ["EHLO", "HELO"] and len(msg_parts) > 1 and msg_parts[0].upper() != "QUIT":
                if msg_parts[1].lower() == "server" or msg_parts[1] in [socket.gethostname(), socket.gethostbyname(socket.gethostname())]:
                    rep = f"250 Hello {socket.gethostname()} [{socket.gethostbyname(socket.gethostname())}], pleased to meet you"
                    c.send(rep.encode())
                    
                    while msg.upper()!="QUIT":
                        if authorized:
                            rep = "Enter QUIT to end email session\n[or send another email]\nMAIL FROM [Only Enter Email Address]: "
                            c.send(rep.encode())
                            logger(frohost, tohost, msg, rep)
                            
                            msg = c.recv(1024).decode()
                            logger(frohost, tohost, msg, '')
                            
                            if not msg.upper() == "QUIT" and not msg.upper().startswith("HELP"):
                                msg = "MAIL FROM: " + msg
                        else:                
                            rep = "Send the AUTH Command, and enter your username and password for the prompts that follow. If you aren't already registered, a temporary password will be created."           
                            c.send(rep.encode())
                            logger(frohost, tohost, "AUTH", rep)
                            
                            msg = c.recv(1024).decode().lower()
                            logger(frohost, tohost, "AUTH", msg)
                            
                        f, t, data, msg, authorized, u_name = init(msg, c, valid_commands, authorized, u_name)
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
                    rep = f"501 Syntax error in parameters or arguments: {msg}"
                    c.send(rep.encode())
                    logger(frohost, tohost, msg, rep)
            elif msg.upper() == "QUIT":
                pass    
            elif msg.upper().startswith("HELP"):
                helper(msg, c, valid_commands) # help message function
                # msg = c.recv(1024).decode()
                # f, t, data, msg, authorized, u_name = init(msg, c, valid_commands, authorized)
                continue
            elif msg_parts[0].upper() in ["EHLO", "HELO"] and len(msg_parts) <= 1:
                rep = "504 Command parameter not implemented"
                c.send(rep.encode())
                logger(frohost, tohost, msg, rep)
                
            elif msg.upper().split(':')[0] in valid_commands:
                rep = "503 Polite people say HELO first"
                c.send(rep.encode())
                logger(frohost, tohost, msg, rep)
            else:
                rep = f"500 Command unrecognised: {msg}"
                c.send(rep.encode())
                logger(frohost, tohost, msg, rep)
            
            if msg.upper() == "QUIT":
                rep = f"421 {socket.gethostname()} Service closing transmission channel"
                c.send(rep.encode())
                logger(frohost, tohost, msg, rep)
                print(f"{addr} has disconnected")
                
    except Exception as e:
        print(e)
        logger(frohost, tohost, str(e), '')

def smtp_email_server(tcp_port:int):
    global auth_smtp_done
    
    print('Starting SMTP Email Server, Enter PEM passphrase "447s20" when prompted...')
    try:
        if not os.path.exists("db"):
            os.mkdir('db')

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        
        ctx.options |= ssl.OP_NO_TLSv1
        ctx.options |= ssl.OP_NO_TLSv1_1
        ctx.load_cert_chain(certfile='proj_3.cert', keyfile="proj_3.key", password=None)
        # ctx.load_verify_locations("447s20.cert")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', tcp_port))        
        s.listen()
        
        hostname = socket.gethostbyname(socket.gethostname())
        secure_s = ctx.wrap_socket(s, server_hostname=hostname)
        # secure_s = ssl.wrap_socket(sock=s, server_side=True, certfile='447s20.cert', keyfile='447s20.key', cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLSv1_2) # 2.7
        print(f"{datetime.now().strftime('%a, %b %d %Y %H:%M:%S')} {int((timegm(localtime()) - timegm(gmtime()))/3600):03d} TCP Server is now waiting for client connections on ({socket.gethostbyname(socket.gethostname())})...")
        auth_smtp_done = True
        while True:
            c, addr = secure_s.accept()
            # c = ctx.wrap_socket(c, server_side=True)
            threading.Thread(target=smtp, args=((c, addr))).start()
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
        logger("SSL ERROR", '', str(e), '')
    except Exception as e:
        print(f"SMTP Connection error: {e}")
        logger("SMTP CONNECTION ERROR", '', str(e), '')
    finally:
        try:
            s.close()            
        except Exception:
            pass
        try:
            secure_s.close()            
        except Exception:
            pass
        smtp_email_server(tcp_port)
        
def http_200_response_formatter(content_type, msg=None, i=None, count=None, filename=None, body=None):
    """Build HTTP 200 Response"""
    header = f"HTTP/1.1 200 OK\n"\
            f"Server: {socket.gethostbyname(socket.gethostname())}\n"\
            f"Last-Modified: {datetime.now().strftime('%a, %b %d %Y %H:%M:%S')} {int((timegm(localtime()) - timegm(gmtime()))/3600):03d}\n"\
            f"Content-Type: {content_type}\n"
    if count:
        header +=  f"Count: {count}\n"
    if msg:
        header += f"Message: {i}\n\n"
    if body:
        header += body
    if filename and not body:
        with open(filename, 'r') as fin:
            body = fin.read()
        header += body
        
    return header

def receiver_connection_handler(ctx, PORT, creds, username):  
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_addr = ('', PORT)
        sock.bind(server_addr)
        sock.listen()
        
        hostname = socket.gethostbyname(socket.gethostname())
        secure_sock = ctx.wrap_socket(sock, server_hostname=hostname)
        
        s, addr = secure_sock.accept()
        s.settimeout(2000) # password timeout
        request = s.recv(1024)
        
        frohost = socket.gethostbyname(socket.gethostname())
        tohost, toport = s.getpeername()
        
        s.settimeout(None)
        logger(frohost, tohost, request.decode(), '')
        
        request = request.decode().splitlines()
        password = json.loads(request[-1:][0].strip("Authentication: "))["password"]
        password = int(base64.b64decode(password).decode())
        password = hash_pw(password, bytes.fromhex(creds[username][1]))
        
        if bytes.fromhex(creds[username][0]) == password:
            # get num mails needed
            rep = "235 Authentication Succeeded"
            s.send(rep.encode())
            logger(frohost, tohost, rep, '')
            
        else:
            rep = "535 Authentication credentials are invalid"
            s.send(rep.encode())
            logger(frohost, tohost, rep, '')
            return
        
        username = base64.b64decode(username).decode()
        while True:
            req = s.recv(1024)
            logger(frohost, tohost, req.decode(), '')
            
            req = req.decode()
            if req.split()[1] == "email_info":
                # pop3 standard so get all files cuz the ones already read have been deleted
                if os.path.exists(f"db/{username.split('@')[0]}"):
                    unread = glob(f"db/{username.split('@')[0]}/*.email")
                    rep = http_200_response_formatter(
                            content_type= "application/json",
                            body = f"Number of unread emails: {len(unread)}"
                        )
                    s.send(rep.encode())
                    logger(frohost, tohost, rep, '')
                    if len(unread) == 0:
                        rep = "404 No Emails Found"
                        s.send(rep.encode())
                        logger(frohost, tohost, rep, '')
                        break
                    
                    req = s.recv(1024)
                    logger(frohost, tohost, req.decode(), '')
                    print(req.decode())
                    req = req.decode().splitlines()
                    num_to_retrieve = int(req[-1:][0].strip("Count: "))
                    buffer = []
                    if len(req) >= 3 and num_to_retrieve > 0:
                        dest_user_name = req[0].split()[1]
                        if os.path.exists(dest_user_name.strip('/')):
                            emails = glob(f"{dest_user_name.strip('/')}/*.email")
                            emails = sorted(emails)
                            
                            
                            if len(emails) >= num_to_retrieve: # check if count is valid
                                emails_to_send = emails[0:num_to_retrieve]
                                rep = "200 OK"
                                s.send(rep.encode())
                                logger(frohost, tohost, rep, '')
                                for i in range(0, num_to_retrieve):
                                    buffer.append(http_200_response_formatter(content_type="text/plain", filename=emails_to_send[i], msg=i+1, count=num_to_retrieve))                                    
                            else:
                                rep = f"200 OK: {len(emails)} emails available"
                                s.send(rep.encode())
                                logger(frohost, tohost, rep, '')
                                
                                emails_to_send = emails
                                for i in range(0, len(emails)):
                                    buffer.append(http_200_response_formatter(content_type="text/plain", filename=emails_to_send[i], msg=i+1, count=len(emails)))
                            
                            for email in emails_to_send: # delete sent files
                                os.remove(email)
                            emails_to_del = emails[num_to_retrieve:] # rename unread files
                            for i in range(0, (len(emails_to_del))):
                                os.rename(emails_to_del[i], f"{dest_user_name.strip('/')}/{i+1:03d}.email")
                            
                            s.send(f"\n{'-'*60}\n".join(buffer).encode())
                            logger(frohost, tohost, f"{username} Retrieved {len(emails_to_send)} emails", '')
                    else:
                        rep = "400 Bad Request"
                        s.send(rep.encode())
                        logger(frohost, tohost, rep, '')
                else:
                    rep = "404 No Emails Found"
                    s.send(rep.encode())
                    logger(frohost, tohost, rep, '')
                    break
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
        logger("SSL ERROR", '', str(e), '')
    except socket.timeout:
            rep = f"HTTP connection timeout at port: {PORT}"
            print(rep)
            logger(frohost, '', rep, '')
            s.settimeout(None)
    finally:
        try:
            sock.close()            
        except Exception:
            pass
        try:
            secure_sock.close()            
        except Exception:
            pass

    
def http_server(http_port:int):
    try:
        print('Starting HTTP Receiver Server, Enter PEM passphrase "447s20" when prompted...')
        
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ctx.options |= ssl.OP_NO_TLSv1
        ctx.options |= ssl.OP_NO_TLSv1_1
        ctx.load_cert_chain(certfile='proj_3.cert', keyfile="proj_3.key", password=None)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_addr = ('', http_port)
        sock.bind(server_addr)
        new_port = http_port + 1
        used_ports = []
        sock.listen()
        
        hostname = socket.gethostbyname(socket.gethostname())
        secure_sock = ctx.wrap_socket(sock, server_hostname=hostname)
        
        print(f"{datetime.now().strftime('%a, %b %d %Y %H:%M:%S')} {int((timegm(localtime()) - timegm(gmtime()))/3600):03d} HTTP Server is now waiting for client requests on ({socket.gethostbyname(socket.gethostname())})...")
        while True:
            s, addr = secure_sock.accept()
            
            request = s.recv(1024)
            
            frohost = socket.gethostbyname(socket.gethostname())
            tohost, toport = s.getpeername() 
            logger(frohost, tohost, request.decode(), '')
            
            print(f"Request from: {addr}")
            print(request.decode())
            request = request.decode().splitlines()
            user = json.loads(request[-1:][0].strip("Authentication: "))
            username = user["username"]
            # password = base64.b64decode(bytes(str(int(base64.b64decode(auths["password"]).decode())+447), 'ascii'))
            if os.path.exists('db/.user_pass'):
                with open('db/.user_pass', 'r') as creds_file:
                    creds = json.loads(creds_file.read())
            else:
                creds = {}
                
            if username in creds:
                while new_port in used_ports:
                    new_port += 1
                used_ports.append(new_port)
                if '@' in base64.b64decode(username).decode().strip("@447.edu"):
                    response = f"535 Invalid Domain"
                else:
                    response = http_200_response_formatter(
                            content_type='application/json',
                            body = f'{{"reply_code": "334 cGFzc3dvcmQ6 [enter password]", "forward_port": {new_port}}}'
                        )
                s.send(response.encode())
                logger(frohost, tohost, response, '')
                
                threading.Thread(target=receiver_connection_handler, args=((ctx, new_port, creds, username))).start()
                
                print(f"Forwarded HTTP connection from port {http_port} to {new_port}")
            elif '@' in base64.b64decode(username).decode().strip("@447.edu"):
                rep = f"535 Invalid Domain"
                s.send(rep.encode())
                logger(frohost, tohost, rep, '')
            else:
                pw = randint(10000, 99999)
                rep = f"330 Temp. Password: {pw}"
                s.send(rep.encode())
                logger(frohost, tohost, rep, '')
                salt = os.urandom(32)
                creds[username] = (hash_pw(pw, salt).hex(), salt.hex())
                with open('db/.user_pass', 'w+') as file:
                    json.dump(creds, file)
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
        logger("SSL ERROR", '', str(e), '')
    except Exception as e:
        print(f"HTTP error on port {new_port} : {e}")
        logger(f"HTTP error on port {new_port}", '', str(e), '')
    finally:
        try:
            sock.close()            
        except Exception:
            pass
        try:
            secure_sock.close()            
        except Exception:
            pass
        http_server(http_port)
            
if __name__ == "__main__":
    try:
        send_port = int(sys.argv[1])
        recv_port = int(sys.argv[2])
    except Exception as e:
        print(f"{e}\n\nExpected: python server.py <SMTP_Server_Port> <HTTP_Server_Port>")
    
    if not os.path.exists('.server_log'):
        create_log_file()
    
    auth_smtp_done = False

    threading.Thread(target=smtp_email_server, args=[send_port]).start() # smtp thread tree
    while not auth_smtp_done:
        pass
    threading.Thread(target=http_server, args=[recv_port]).start() # http thread tree