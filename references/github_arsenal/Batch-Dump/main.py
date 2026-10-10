from watchdog.events import FileSystemEventHandler
from rgbprint import gradient_print, Color
from watchdog.observers import Observer
from colorama import Fore
import shutil
import time
import os


class utility:
    logo = """                             :::::::::  :::    :::   :::   :::   ::::::::: ::::::::::: :::::::::: :::   ::: 
                            :+:    :+: :+:    :+:  :+:+: :+:+:  :+:    :+:    :+:     :+:        :+:   :+:  
                           +:+    +:+ +:+    +:+ +:+ +:+:+ +:+ +:+    +:+    +:+     +:+         +:+ +:+    
                          +#+    +:+ +#+    +:+ +#+  +:+  +#+ +#++:++#+     +#+     :#::+::#     +#++:      
                         +#+    +#+ +#+    +#+ +#+       +#+ +#+           +#+     +#+           +#+        
                        #+#    #+# #+#    #+# #+#       #+# #+#           #+#     #+#           #+#         
                       #########   ########  ###       ### ###       ########### ###           ###""" # Logo art

    menu = """
                                                ╔═══                    ═══╗
                                                   [1] Dump compiled Batch   
                                                   [2] Deobfuscate Batch
                                                ╚═══                    ═══╝""" # Menu art

    possible_paths = [
        os.path.join(os.getenv("LOCALAPPDATA"), "Temp"),  
        os.getenv("APPDATA"),
        os.path.join(os.path.expanduser("~"), "Desktop"),  
        os.path.join(os.path.expanduser("~"), "Documents"),
        os.path.join(os.path.expanduser("~"), "Pictures"), 
        os.path.join(os.path.expanduser("~"), "Music"),  
        os.path.join(os.path.expanduser("~"), "Videos"), 
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.environ["ProgramW6432"], 
        os.environ["ProgramData"]  
    ]


    def delete_hex(path: str, hex: str): # Function to delete specific hex bytes from a file
        with open(path, 'rb') as f: # Open the file in binary read mode
            src = f.read() # Read the file content

        hex_bytes = bytes.fromhex(hex) # Convert hex string to bytes

        new = src.replace(hex_bytes, b'') # Remove the specified hex bytes

        with open(path, 'wb') as f: # Open the file in binary write mode
            f.write(new) # Write the modified content back to the file

    def watchdog(dir: str, current_path: str):
        try:
            handle = utility.FileCreationHandler(current_path) # Try to create a file creation handle
            observer = Observer() # Create an Observer instance
            observer.schedule(handle, dir, recursive=True) # Schedule the observer to monitor the directory
            observer.start() # Start the observer

            try:
                while True:
                    time.sleep(1) # Keep the script running
            except KeyboardInterrupt: # Handle keyboard interrupt
                observer.stop() # Stop the observer

            observer.join() # Wait for the observer to finish
        except Exception as e:
            print(f"{Fore.RESET} [{Fore.RED}!{Fore.RESET}] Could not access the directory {Fore.RED}>{Fore.RESET} {dir} {Fore.LIGHTBLACK_EX}({e}){Fore.RESET}") # Print error message if directory cannot be accessed


    class FileCreationHandler(FileSystemEventHandler): # Event handler for file creation
        def __init__(self, dir): # Initialize the event handler
            super().__init__() # Initialize the parent class
            self.dir = dir # Directory to copy detected files to
            self.files = set() # To keep track of already processed files

        def on_created(self, event): # Handle file creation events
            if not event.is_directory and event.src_path.endswith(".bat"): # Check if the created file is a batch file
                if event.src_path not in self.files:  # Check if the file has already been processed
                    dest_path = os.path.join(self.dir, os.path.basename(event.src_path)) # Destination path for the copied file
                    print(f"{Fore.RESET} [{Fore.GREEN}+{Fore.RESET}] Found a Possible Source Code {Fore.GREEN}>{Fore.RESET} {event.src_path}") # Notify user of detected batch file
                    try: # Try to copy the detected batch file
                        shutil.copy(event.src_path, dest_path) # Copy the detected batch file to the current script directory
                    except Exception as e: # Handle exceptions during file copy
                        print(f"{Fore.RESET} [{Fore.RED}!{Fore.RESET}] Error while copying file {Fore.RED}>{Fore.RESET} {str(e)}") # Print error message if file cannot be copied

                    self.files.add(event.src_path) # Mark the file as processed


class BatchDump:
    @staticmethod
    def dump():
        os.system("cls" if os.name == "nt" else "clear") # Clear the console
        os.system("mode 135,30" if os.name == "nt" else "printf '\e[8;30;135t'") # Set console size
        gradient_print(utility.logo, start_color=Color.lawn_green, end_color=Color.ghost_white) # Print logo with a nice color gradient

        print(f"\n{Fore.RESET} [{Fore.GREEN}+{Fore.RESET}] Please open the target compiled batch file now. I will try to detect it.") # Prompt user to open the batch file

        current_path = os.path.dirname(os.path.abspath(__file__)) # Get the current script directory

        for dir in utility.possible_paths:
            utility.watchdog(dir, current_path) # Call watchdog for each possible path

    @staticmethod
    def deobfuscate():
        os.system("cls" if os.name == "nt" else "clear") # Clear the console
        os.system("mode 135,30" if os.name == "nt" else "printf '\e[8;30;135t'") # Set console size
        gradient_print(utility.logo, start_color=Color.lawn_green, end_color=Color.ghost_white) # Print logo with a nice color gradient

        batch_path = input(f"\n{Fore.RESET} [{Fore.GREEN}+{Fore.RESET}] Enter the path to the batch file >{Fore.GREEN} ").strip().strip('"') # Input for batch file path
        if not os.path.isfile(batch_path): # Check if the file exists
            print() # New line for better readability
            print(f"{Fore.RESET} [{Fore.RED}!{Fore.RESET}] The specified file does not exist. Please restart the program and provide a valid file path.") # Error message
            return
        
        utility.delete_hex(batch_path, "FF FE 26 63 6C 73 0D 0A FF FE 0A 0D") # Remove specific hex bytes from the batch file to deobfuscate it
        
        os.system("start notepad.exe " + batch_path if os.name == "nt" else "xdg-open " + batch_path) # Open the deobfuscated batch file in Notepad or default text editor
        
        print() # New line for better readability
        print(f"{Fore.RESET} [{Fore.GREEN}+{Fore.RESET}] Deobfuscation complete! The batch file has been successfully deobfuscated.") # Success message
        return
    
    @staticmethod
    def error():
        print() # New line for better readability
        print(f"{Fore.RESET} [{Fore.RED}!{Fore.RESET}] Invalid choice! Please restart the program and select a valid option from the menu.") # Error message


def main():
    os.system("cls" if os.name == "nt" else "clear") # Clear the console
    os.system("mode 135,30" if os.name == "nt" else "printf '\e[8;30;135t'") # Set console size
    gradient_print(utility.logo, start_color=Color.lawn_green, end_color=Color.ghost_white) # Print logo with a nice color gradient
    gradient_print(utility.menu, start_color=Color.lawn_green, end_color=Color.ghost_white) # Print menu with a nice color gradient

    choice = input(f"{Fore.RESET} [{Fore.GREEN}+{Fore.RESET}] Enter your choice (1-2) >{Fore.GREEN} ") # Input for user choice

    if choice == "1": # If user chooses to dump batch
        BatchDump.dump() # Call the dump function
    elif choice == "2": # If user chooses to deobfuscate batch
        BatchDump.deobfuscate() # Call the deobfuscate function
    else:
        BatchDump.error() # Call the error function for invalid choice

if __name__ == "__main__":
    main()