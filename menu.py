import os
import requests
import socket
import dns.resolver
import ssl
from OpenSSL import SSL

# Get the path to the directory where the main Python file resides
current_directory = os.path.dirname(os.path.abspath(__file__))

# Get a list of all Python files with a .py extension in the current directory
python_files = [file for file in os.listdir(current_directory) if file.endswith('.py')]

# Filter out the main Python file from the list of available files
main_file_name = os.path.basename(__file__)
available_files = {file[:-3]: os.path.join(current_directory, file) for file in python_files if file != main_file_name}

def run_selected_file(file_path):
    try:
        with open(file_path) as file:
            code = compile(file.read(), file_path, 'exec')
            exec(code, globals(), locals())
    except FileNotFoundError:
        print(f"'{file_path}' file does not exist.")
    except Exception as e:
        print(f"An error occurred while running '{file_path}': {e}")

def create_gui():
    print("Select a Python file to run:")
    for i, (file_name, _) in enumerate(available_files.items(), 1):
        print(f"{i}. {file_name.capitalize()}")

    while True:
        choice = input("\nEnter the number of the Python file to run: ")
        if not choice.isdigit():
            print("Invalid input. Please enter a valid number.")
        else:
            choice = int(choice) - 1
            if 0 <= choice < len(available_files):
                selected_file = list(available_files.values())[choice]
                run_selected_file(selected_file)
                break
            else:
                print("Invalid choice. Please enter a valid number.")


if __name__ == "__main__":
    create_gui()

