import sys
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
import random
import string
import pyperclip
from PyQt6.QtGui import QIcon
import os
import requests

class PasswordGenerator(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.generated_password = ""
        self.setFixedSize(300, 250)

    def init_ui(self):
        layout = QVBoxLayout()

        self.length_label = QLabel("Password Length:")
        self.length_input = QLineEdit()
        self.generate_button = QPushButton("Generate and Copy Password")
        self.show_password_button = QPushButton("Show Password")
        self.generated_password_output = QTextEdit()
        self.generated_password_output.setReadOnly(True)
        self.normal_password_checkbox = QPushButton("Generate and Copy 'Normal' Password")

        self.generate_button.clicked.connect(self.generate_and_copy_password)
        self.show_password_button.clicked.connect(self.show_password)
        self.normal_password_checkbox.clicked.connect(self.normal_password_changed)

        layout.addWidget(self.length_label)
        layout.addWidget(self.length_input)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.normal_password_checkbox)
        layout.addWidget(self.show_password_button)
        layout.addWidget(self.generated_password_output)
        

        self.setLayout(layout)
        self.set_app_icon()

        self.setWindowTitle("Password Generator")

        self.show_password_button.setEnabled(False)

    def set_app_icon(self):
        icon_path = self.get_icon_path()
        if not os.path.exists(icon_path):
            
            icon_url = "https://raw.githubusercontent.com/serctn/Chinese-Password-Generator/main/icon.ico"
            response = requests.get(icon_url)
            if response.status_code == 200:
                with open(icon_path, "wb") as f:
                    f.write(response.content)

        self.setWindowIcon(QIcon(icon_path))

    def get_icon_path(self):
        if sys.platform.startswith('win32'):
            icon_dir = os.path.join(os.getenv('LOCALAPPDATA'), 'PasswordGenerator')
        else:
            icon_dir = os.path.join(os.getenv('HOME'), '.local', 'share', 'PasswordGenerator')

        os.makedirs(icon_dir, exist_ok=True)

        return os.path.join(icon_dir, 'icon.ico')

    def normal_password_changed(self):
        length_text = self.length_input.text()
        if not length_text:
            self.generated_password_output.setPlainText("Please enter the password length.")
            return

        length = int(length_text)
        if length < 4:
            self.generated_password_output.setPlainText("Password length should be at least 4 characters.")
            return
        
        latin_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        latin_small = "abcdefghijklmnopqrstuvwxyz"
        digits = string.digits
        special_characters = string.punctuation

        all_characters = latin_letters + latin_small + digits + special_characters 

        # Generate password
        password = random.choice(latin_letters) + \
                   random.choice(latin_small) + \
                   random.choice(digits) + \
                   random.choice(special_characters)

        remaining_count = length - 4
        password += ''.join(random.choice(all_characters) for _ in range(remaining_count))

        password_list = list(password)
        random.shuffle(password_list)
        password = ''.join(password_list)

        pyperclip.copy(password)

        self.generated_password_output.clear()
        self.generated_password_output.setPlaceholderText("Password generated and copied to clipboard.")
        self.show_password_button.setEnabled(True)
        self.generated_password = password

    def generate_and_copy_password(self):
        length_text = self.length_input.text()
        if not length_text:
            self.generated_password_output.setPlainText("Please enter the password length.")
            return

        length = int(length_text)
        if length < 18:
            self.generated_password_output.setPlainText("Password length should be at least 18 characters.")
            return
        
        latin_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        latin_small = "abcdefghijklmnopqrstuvwxyz"
        digits = string.digits
        special_characters = string.punctuation
        cyrillic_russian_letters = ''.join([chr(char_code) for char_code in range(0x0400, 0x052F)])
        cyrillic_bulgarian_letters = ''.join([chr(char_code) for char_code in range(0x0410, 0x044F)])
        cyrillic_serbian_letters = ''.join([chr(char_code) for char_code in range(0x040A, 0x040F)])
        cyrillic_macedonian_letters = ''.join([chr(char_code) for char_code in range(0x0400, 0x040F)]) + "ЌќЅѕЏџ"
        cyrillic_ukrainian_letters = ''.join([chr(char_code) for char_code in range(0x0400, 0x04FF)])
        cyrillic_belarusian_letters = ''.join([chr(char_code) for char_code in range(0x0400, 0x052F)])
        cyrillic_bosnian_croatian_montenegrin_slovenian_letters = ''.join([chr(char_code) for char_code in range(0x0400, 0x052F)])
        greek_letters = ''.join([chr(char_code) for char_code in range(0x0370, 0x03FF)])
        chinese_characters = ''.join([chr(char_code) for char_code in range(0x4E00, 0x9FFF)])
        japanese_characters = ''.join([chr(char_code) for char_code in range(0x3040, 0x30FF)])
        korean_characters = ''.join([chr(char_code) for char_code in range(0x1100, 0x11FF)])
        german_letters = 'äöüßÄÖÜ'
        spanish_letters = 'áéíóúüñ¿¡ÁÉÍÓÚÜÑ'
        french_letters = 'àâæçéèêëîïôœùûüÿÀÂÆÇÉÈÊËÎÏÔŒÙÛÜŸ'

        all_characters = latin_letters + latin_small + digits + special_characters + \
                         cyrillic_russian_letters + cyrillic_bulgarian_letters + cyrillic_serbian_letters + cyrillic_macedonian_letters + \
                         cyrillic_ukrainian_letters + cyrillic_belarusian_letters + cyrillic_bosnian_croatian_montenegrin_slovenian_letters + \
                         greek_letters + chinese_characters + japanese_characters + korean_characters + \
                         german_letters + spanish_letters + french_letters

        # Generate password
        password = random.choice(latin_letters) + \
                   random.choice(latin_small) + \
                   random.choice(digits) + \
                   random.choice(special_characters) + \
                   random.choice(cyrillic_russian_letters) + \
                   random.choice(cyrillic_bulgarian_letters) + \
                   random.choice(cyrillic_serbian_letters) + \
                   random.choice(cyrillic_macedonian_letters) + \
                   random.choice(cyrillic_ukrainian_letters) + \
                   random.choice(cyrillic_belarusian_letters) + \
                   random.choice(cyrillic_bosnian_croatian_montenegrin_slovenian_letters) + \
                   random.choice(greek_letters) + \
                   random.choice(chinese_characters) + \
                   random.choice(japanese_characters) + \
                   random.choice(korean_characters) + \
                   random.choice(german_letters) + \
                   random.choice(spanish_letters) + \
                   random.choice(french_letters)

        remaining_count = length - 18
        password += ''.join(random.choice(all_characters) for _ in range(remaining_count))

        password_list = list(password)
        random.shuffle(password_list)
        password = ''.join(password_list)

        pyperclip.copy(password)

        self.generated_password_output.clear()
        self.generated_password_output.setPlaceholderText("Password generated and copied to clipboard.")
        self.show_password_button.setEnabled(True)
        self.generated_password = password
        
    def show_password(self):
        self.generated_password_output.setPlainText(self.generated_password)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  
    window = PasswordGenerator()
    window.show()
    sys.exit(app.exec())
