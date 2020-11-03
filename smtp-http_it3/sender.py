# sender.py

import socket
import sys 
import base64
import time
import re
import json
import ssl

def domain_check(msg):
        return msg.split('@')[1] == "447.edu"
    
def validate_certificate(cert):
    pass


if __name__ == "__main__":
    try:
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])
    except IndexError:
        print("Required args have not been provided (hostname and port)")
    
    try: 
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations("proj_3.cert")
        s = socket.socket()
        s.connect((HOST, PORT))      
        secure_s = ctx.wrap_socket(s, server_hostname=HOST, server_side=False)
        
        peer_cert = secure_s.getpeercert()
        # Validating certificate manually to prevent errors as the server is not being run on one manchine forever, but on different machines
        # but the same certificate can be used on all machines
        # ssl.match_hostname() function is deprecated as of python 3.7 but fullfills the purpose of a certificate validation for this project.
        # bmohan-smtp-http.com = mock hostname to validate certificate
        ssl.match_hostname(peer_cert, "bmohan-smtp-http.com")
        print("Certificate Validation Successful")
        #------------------------------------------------------------------------------------------------------------------------------------#
        
        print(f"Connected to {socket.gethostbyname(socket.gethostname())}")
        print(secure_s.recv(1024).decode()) # confirmation
        
        inp = ''
        resp = ''
        while inp.upper()!= "QUIT":
            inst = secure_s.recv(1024).decode() # instructions to user
            if "MAIL FROM" in inst or "RCPT TO" in inst:
                inp = ''
                while not inp:
                    inp = input(inst).lower()
            else:
                print(inst)
                while not inp:
                    inp = input('')
            to_send = ''
            
            if inp.upper() == "AUTH":
                secure_s.send(inp.encode())
                resp = secure_s.recv(1024).decode()
                print(resp)
                while resp.startswith("334"):
                    inp = input()
                    inp = inp.lower() # username
                    if resp=="334 dXNlcm5hbWU6":
                        if '@' in inp and not re.search(r'[\\/*?:"<>|]', inp) and inp.split('@')[1] == "447.edu":
                            secure_s.send(base64.b64encode(bytes(inp, 'ascii')))
                            resp = secure_s.recv(1024).decode()
                            print(resp)
                        else:
                            print("Domain not provided or is invalid - re-enter email")
                    elif resp=="334 cGFzc3dvcmQ6":
                        if inp.isdigit():
                            pw = str(int(inp))
                            secure_s.send(base64.b64encode(bytes(pw, 'ascii')))
                            resp = secure_s.recv(1026).decode() # password sucess or fail response
                            print(resp)
                        else:
                            print("Re-enter Password: Must be numeric")
                if resp.startswith("330"):
                    secure_s.close()
                    s.close()
                    print("Reconnecting...")
                    time.sleep(5) # sleep for 5
                    s = socket.socket()
                    s.connect((HOST, PORT))
                    secure_s = ctx.wrap_socket(s, server_side=False, server_hostname=HOST)
                    print(f"Reconnected to {socket.gethostbyname(socket.gethostname())}")
                    print(secure_s.recv(1024).decode()) # confirmation

            elif inp.upper() == "DATA":
                secure_s.send(inp.encode())
                resp = secure_s.recv(1024).decode() 
                print(resp)
                inp = ''
                if resp.startswith('354'): # if reply code is greater than 300, 354 to type data
                    while inp != '.':
                        to_send += inp+'\n'
                        inp = input()
            else:
                to_send = inp
                if inp.upper()!= "QUIT":
                    inp = ''
            
            if to_send != '':
                secure_s.send(to_send.encode())
                resp = secure_s.recv(1024).decode()
                print(resp)
                    
            
        # if inp.upper() == "QUIT":
        #     secure_s.close()
        #     s.close()
    except ssl.CertificateError as e:
        print(f"Invalid SSL certificate provided: {e}")
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
    except Exception as e:
        print(e)
    finally:
        try:
            s.close()            
        except Exception:
            pass
        try:
            secure_s.close()            
        except Exception:
            pass
        print("Exiting client...")