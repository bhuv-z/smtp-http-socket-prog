# SMTP+HTTP Client-Server with AUTH	- TCP & UDP
---
## Language: Python3.6+
## Usage:

	Server:
		- python3 server.py <TCP PORT> <UDP PORT>       (without angle braces)
			- To exit the server has to be force terminated

	
	Sender:
		- python3 sender.py <IP ADDR of machine hosting the server> <TCP PORT>      (without angle braces)
			- Greet the server with "HELO server" OR "EHLO server"
			- USE "HELP" to get list of commands and Usage
			- Use the AUTH command to provide your credentials to access the email service. 
				If you have not registered already, a password will be created by the server.
			- To write an email, Start with "MAIL FROM" after initiating email session

	Receiver:
		- python3 receiver.py <IP ADDR of machine hosting the server> <TCP PORT>      (without angle braces)
			- Provide authentication information when propted
			- Enter inputs for the prompts to retreive emails


	DB:
		db/.user_pass
			- stores user credentials
			- is not visible when using "ls" on linux
			- Display file contents using: 	cat db/.user_pass 	
		
	Logs
		.server_log
			- keeps track of messages sent and received by the server
			- is not visible when using "ls" on linux
			- Display file contents using: 	cat .server_log
