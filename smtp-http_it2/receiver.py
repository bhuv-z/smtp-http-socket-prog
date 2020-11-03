# receiver.py

import socket
import sys
import os
from glob import glob
import re
import json
import base64


if __name__ == "__main__":
    try:
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])
    except IndexError:
        print("Required args have not been provided (hostname and port)")
        
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (HOST, PORT)
    
    
    def build_req(get_statement, host, req):
        return f"GET {get_statement} HTTP/1.1\n"\
                f"Host: {HOST}\n"\
                f"{req}"

    user_name = input("Enter Username: ").strip('<').strip('>').lower()
    # password = input("Enter password: ")
    
    try:
        if user_name != '':
            if not os.path.exists(f"{user_name.split('@')[0]}"):
                os.mkdir(f"{user_name.split('@')[0]}")
            if not user_name.endswith("@447.edu"):
                user_name += "@447.edu"

            if not re.search(r'[\\/*?:"<>|]', user_name):
                un = base64.b64encode(bytes(user_name, 'ascii'))
                # pw = base64.b64encode(bytes(password, 'ascii'))
                authentication_req = build_req("auth", HOST,
                                                f'Authentication: {{"username":"{un.decode()}"}}')
                s.sendto(authentication_req.encode(), server_addr)
                data, server = s.recvfrom(1024) # overall status - to console
                data = data.decode().splitlines()
                  
                if data[0].split()[1] == "200":
                    resp = json.loads(data[-1:][0])
                    print(resp["reply_code"])
                    PORT = resp["forward_port"]
                    # assign new port
                    server_addr = (HOST, PORT)
                    
                    # password auth
                    password = input("Enter password: ")
                    if not password.isdigit():
                        raise Exception("Invalid password - closing connection")

                    pw = base64.b64encode(bytes(password, 'ascii'))
                    authentication_req = build_req("auth", HOST,
                                                f'Authentication: {{"password":"{pw.decode()}"}}')
                    
                    s.sendto(authentication_req.encode(), server_addr)
                    
                    # auth confirmation
                    data, server = s.recvfrom(1024)
                    data = data.decode()
                    
                    if data.startswith("235"):
                        print(data)
                        while True:
                            # emails available
                            s.sendto(f"GET email_info".encode(), server)
                            data, server = s.recvfrom(1024)
                            data = data.decode().splitlines()
                            
                            if data[0].split()[1] == "200":
                                print(data[-1:][0])
                                num_unread = int(data[-1:][0].split(': ')[1])
                                if num_unread > 0:
                                    all_msgs = input("Would you like to retrieve all messages? [Y/n]: ")
                                    if all_msgs.lower() == 'y':
                                        get_req = build_req(f"/db/{user_name.split('@')[0]}", HOST,
                                                            f"Count: {num_unread}")
                                    else:
                                        num_lookup = input('Enter number of emails to fetch [or "exit" to close connection] : ')
                                        
                                        if not num_lookup.isdigit(): 
                                            if num_lookup.lower() == 'exit':
                                                print("Terminating receiver...")
                                                s.close()
                                                exit(0)
                                            else:
                                                print("Enter a valid number of messages to retrieve")
                                                continue
                                        num_lookup = int(num_lookup)  
                                        if num_lookup < 0:
                                            raise Exception("Not a valid number")
                                            
                                    
                                        # get num emails
                                        get_req = build_req(f"/db/{user_name.split('@')[0]}", HOST,
                                                            f"Count: {num_lookup}")
                                else:
                                    print("No messages to retrieve")
                                    break
                                    
                                
                                s.sendto(get_req.encode(), server)
                                data, server = s.recvfrom(1024) # overall status - to console
                                data = data.decode()
                                print(data)
                                if data.startswith("200"):
                                    data, server = s.recvfrom(4096) # email responsesisw
                                    data = data.decode()
                                    existing_responses_list = sorted(glob(f"{user_name.split('@')[0]}/response_*.txt"), reverse=True)
                                    if len(existing_responses_list) > 0:
                                        fn = int(os.path.split(existing_responses_list[0])[-1].strip("response_").strip('.txt'))+1
                                    else:
                                        fn = 1
                                    with open(f"{user_name.split('@')[0]}/response_{fn:03d}.txt", 'w') as fout:
                                        fout.write(data)
                            else:
                                print(data[0])
                                break
                                
                    elif data.startswith("535"):
                        raise Exception(data)
                        
                elif data[0].startswith("330"):
                    # get temp password
                    print(data[0])
                    raise Exception("Restart manually and enter credentials")
                
                elif data.startswith("535"):
                    raise Exception(data)
                    
            else:
                raise Exception("Invalid username")
                
            # might have to change this to separate usename and password repliess
           
        else:
            raise Exception("Invalid Username")
        s.close()
    except ValueError:
        print("Invalid input, Terminating client....")
        s.close()
        exit()
    except Exception as e:
        print(e)
        print("Terminating client...")
        s.close()