# sender.py

import socket
import sys 

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
        
        while inp.upper()!= "QUIT":
            inp = input('')
            to_send = ''
            if inp.upper() == "DATA":
                s.send(inp.encode())
                resp = s.recv(1024).decode() 
                print(resp)
                inp = ''
                if resp[0:3] == '354': # if reply code is greater than 300, 354 to type data
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