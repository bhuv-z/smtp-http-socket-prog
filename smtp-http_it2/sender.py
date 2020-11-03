# sender.py

import socket
import sys 
import base64
import time
import re
import json


def domain_check(msg):
        return msg.split('@')[1] == "447.edu"
    

if __name__ == "__main__":
    try:
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])
    except IndexError:
        print("Required args have not been provided (hostname and port)")
    
    s = socket.socket()
    try: 
        s.connect((HOST, PORT))
        print(f"Connected to {socket.gethostbyname(socket.gethostname())}")
        print(s.recv(1024).decode()) # confirmation
        
        inp = ''
        resp = ''
        while inp.upper()!= "QUIT":
            inst = s.recv(1024).decode() # instructions to user
            if "MAIL FROM" in inst or "RCPT TO" in inst:
                inp = ''
                while inp == '' or inp == '\n':
                    inp = input(inst).lower()
            else:
                print(inst)
                inp = input('')
            to_send = ''
            
            if inp.upper() == "AUTH":
                s.send(inp.encode())
                resp = s.recv(1024).decode()
                print(resp)
                while resp.startswith("334"):
                    inp = input()
                    inp = inp.lower() # username
                    if resp=="334 dXNlcm5hbWU6":
                        if '@' in inp and not re.search(r'[\\/*?:"<>|]', inp) and inp.split('@')[1] == "447.edu":
                            s.send(base64.b64encode(bytes(inp, 'ascii')))
                            resp = s.recv(1024).decode()
                            print(resp)
                        else:
                            print("Domain not provided or is invalid - re-enter email")
                    elif resp=="334 cGFzc3dvcmQ6":
                        if inp.isdigit():
                            pw = str(int(inp))
                            s.send(base64.b64encode(bytes(pw, 'ascii')))
                            resp = s.recv(1026).decode() # password sucess or fail response
                            print(resp)
                            # if resp.startswith("235"):
                            #     inp = input()
                            #     to_send = inp
                        else:
                            print("Re-enter Password: Must be numeric")
                if resp.startswith("330"):
                    s.close()
                    print("Reconnecting...")
                    time.sleep(5) # sleep for 5
                    s = socket.socket()
                    s.connect((HOST, PORT))
                    print(f"Reconnected to {socket.gethostbyname(socket.gethostname())}")
                    print(s.recv(1024).decode()) # confirmation

            elif inp.upper() == "DATA":
                s.send(inp.encode())
                resp = s.recv(1024).decode() 
                print(resp)
                inp = ''
                if resp.startswith('354'): # if reply code is greater than 300, 354 to type data
                    while inp != '.':
                        to_send += inp+'\n'
                        inp = input()
            else:
                to_send = inp
            
            if to_send != '':
                s.send(to_send.encode())
                resp = s.recv(1024).decode()
                print(resp)
                    
            
        if inp.upper() == "QUIT":
            print("Exiting client...")
            s.close()
    except Exception as e:
        print(e)