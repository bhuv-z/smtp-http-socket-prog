# SMTP+HTTP Client-Server Interaction With Socket Programming
---
### Language: Python3.6+
### Usage:

	Server:
		- python3 server.py <TCP PORT> <UDP PORT>       (without angle braces)
		- To exit the server has to be force terminated

	
	Sender:
		- python3 sender.py <IP ADDR of machine hosting the server> <TCP PORT>      (without angle braces)
		- initiate email session with "HELO" OR "EHLO"
		- USE "HELP" to get list of commands and Usage
		- To write an email, Start with "MAIL FROM" after initiating email session

	Receiver:
		- python3 receiver.py <IP ADDR of machine hosting the server> <TCP PORT>      (without angle braces)
		- Enter inputs for the promts to retreive emails
