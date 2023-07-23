import os
import PySimpleGUI as sg

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
    layout = [
        [sg.Text("Select a Python file to run:")],
        [sg.DropDown(list(available_files.keys()), key="file_choice", default_value=next(iter(available_files.keys())))],
        [sg.Button("Run", key="run"), sg.Button("Exit", key="exit")]
    ]

    window = sg.Window("Select Python File", layout, finalize=True)

    while True:
        event, values = window.read()

        if event == sg.WINDOW_CLOSED or event == "exit":
            break
        elif event == "run":
            selected_file = available_files.get(values["file_choice"])

            if selected_file:
                output = run_selected_file(selected_file)
                sg.popup_scrolled("Output:", output, title="Result")

    window.close()


if __name__ == "__main__":
    create_gui()
