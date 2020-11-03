# SMTP+HTTP Client-Server with AUTH - Only TCP
---
## Language: Python3.6+
## Usage:

	Server:
		- python3 server.py <TCP SMTP PORT> <TCP HTTP PORT>       (without angle braces)
			- Enter PEM passphrase when prompted for both SMTP and HTTP servers		:	"447s20"
			- To exit the server has to be force terminated
		
		Note: Requires proj_3.cert and proj_3.key files to be placed in the directory of server.py
	
	Sender:
		- python3 sender.py <IP ADDR of machine hosting the server> <TCP SMTP PORT>      (without angle braces)
			- Greet the server with "HELO server" OR "EHLO server"
			- USE "HELP" to get list of commands and Usage
			- Use the AUTH command to provide your credentials to access the email service. 
				If you have not registered already, a password will be created by the server.
			- To write an email, Start with "MAIL FROM" after initiating email session

		Note: Requires proj_3.cert to be placed in the directory of sender.py

	Receiver:
		- python3 receiver.py <IP ADDR of machine hosting the server> <TCP HTTP PORT>      (without angle braces)
			- Provide authentication information when propted
			- Enter inputs for the prompts to retreive emails
			
		Note: Requires proj_3.cert to be placed in the directory of receiver.py

	DB:
		db/.user_pass
			- stores user credentials
			- SHA256 encrypted user-credentials are stored as hex values
			- It is not visible when using "ls" on linux
			- Display file contents using:	cat db/.user_pass
		
	Logs:
		.server_log
			- keeps track of messages sent and received by the server
			- is not visible when using "ls" on linux
			- Display file contents using:	cat .server_log

	PCAP Folder:
		Contains packet capture files for demos included in the report

### Changelog
	- All Network COmmunication now occurs on encrypted TLSv1.2 Channels
	- proj_3.cert and proj_3.key are used to validate server client connections
	- User passwords are now SHA256 encrypted before storing in .user_pass

