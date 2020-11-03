# receiver.py

import socket
import sys
import os
from glob import glob
if __name__ == "__main__":
    try:
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])
    except IndexError:
        print("Required args have not been provided (hostname and port)")
        
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (HOST, PORT)
    
    user_name = input("Enter Username: ")
    try:
        if user_name != '':
            if not os.path.exists(f"{user_name.split('@')[0]}"):
                os.mkdir(f"{user_name.split('@')[0]}")
            num_lookup = int(input("Enter number of emails to fetch: "))
            if num_lookup < 0:
                print("Negative numbers aren't valid")
            get_req = f"GET /db/{user_name.split('@')[0]}/ HTTP/1.1\n"\
                    f"Host: {HOST}\n"\
                    f"Count: {num_lookup}"
            s.sendto(get_req.encode(), server_addr)
            
            data, server = s.recvfrom(1024) # overall status - to console
            data = data.decode()
            print(data)
            if data.startswith("200"):
                data, server = s.recvfrom(4096) # email responses
                data = data.decode()
                existing_responses_list = sorted(glob(f"{user_name.split('@')[0]}/response_*.txt"), reverse=True)
                if len(existing_responses_list) > 0:
                    fn = int(os.path.split(existing_responses_list[0])[-1].strip("response_").strip('.txt'))+1
                else:
                    fn = 1
                with open(f"{user_name.split('@')[0]}/response_{fn:03d}.txt", 'w') as fout:
                    fout.write(data)
        else:
            print("Invalid Username")
        s.close()
    except ValueError:
        print("Invalid input, Terminating client....")
        s.close()
        exit()
    except Exception as e:
        print(e)