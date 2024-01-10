# Import necessary libraries
from pwn import *  # pwn is a library used for crafting exploits and handling logs
import sys  # sys is used to handle command-line arguments

# Check if the correct number of command-line arguments is given
if len(sys.argv) != 2:
    # Display an error message if the number of arguments is incorrect
    print("Invalid arguments!")
    print(">> {} <sha256sum>".format(sys.argv[0]))  # Provide the correct usage format
    exit()  # Exit the program

# Retrieve the target SHA-256 hash from command-line arguments
wanted_hash = sys.argv[1]
# Define the path to the wordlist file
password_file = "/usr/share/wordlists/rockyou.txt"
attempts = 0  # Initialize a counter for the number of attempts

# Start a log progress to display ongoing attempts
with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
    # Open the wordlist file
    with open(password_file, "r", encoding='latin-1') as password_list:
        # Iterate over each password in the file
        for password in password_list:
            # Strip newline characters and encode the password
            password = password.strip("\n").encode('latin-1')
            # Compute the SHA-256 hash of the password
            password_hash = sha256sumhex(password)
            # Update the status in the log
            p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
            # Check if the computed hash matches the target hash
            if password_hash == wanted_hash:
                # Success message if the password hash is found
                p.success("Password hash found after {} attempts! {} hashes to {}!".format(attempts, password.decode('latin-1'), password_hash))
                exit()  # Exit the program
            attempts += 1  # Increment the attempt counter
