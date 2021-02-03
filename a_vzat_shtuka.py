try:
    from Crypto import Random
    from Crypto.Cipher import AES
    import os
    import os.path
    from os import listdir
    from os.path import isfile, join
    import hashlib
    import pyperclip
    import getpass
    import msvcrt
    import traceback

    if os.name != "nt":
        import curses
        stdscr = curses.initscr()

    # define our clear function
    def clear():
        # for windows
        if os.name == 'nt':
            _ = os.system('cls')

            # for mac and linux(here, os.name is 'posix')
        else:
            _ = os.system('clear')

    def checkYes(mess):
        return len(mess) and mess.strip().lower()[0] == "y"


    def press_any_key():
        print()
        print("Press any key to continue...")
        msvcrt.getch()


    class Encryptor:
        def __init__(self, key):
            self.key = key

        @staticmethod
        def pad(s):
            mess = s
            if not type(mess) == bytes:
                mess = bytes(mess, 'utf-8')
            return mess + b"\0" * (AES.block_size - len(s) % AES.block_size)

        @staticmethod
        def encrypt(message, key, key_size=256):
            message = Encryptor.pad(message)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return iv + cipher.encrypt(message)

        def encrypt_file(self, file_name):
            with open(file_name, 'rb') as file:
                plaintext = file.read()
            enc = Encryptor.encrypt(plaintext, self.key)
            with open(file_name + ".enc", 'wb') as file:
                file.write(enc)

        @staticmethod
        def decrypt(cipherText, key):
            iv = cipherText[:AES.block_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(cipherText[AES.block_size:])
            return plaintext.rstrip(b"\0")

        def decrypt_file(self, file_name):
            with open(file_name, 'rb') as file:
                cipherText = file.read()
            dec = Encryptor.decrypt(cipherText, self.key)
            with open(file_name[:-4], 'wb') as file:
                file.write(dec)


    class Command:
        def __init__(self, opt_string, func):
            self.func = func
            self.opt_string = opt_string


    class Menu:
        def __init__(self):
            # Creates encryptor
            self.encryptor = self.get_encryptor()

            # Set flag to true to close program
            self.close = False

            # Creates commands
            self.commands = (
                Command("Change the Sauce", Menu.update_encryptor),
                Command("Setup Validation", Menu.validation_setup),
                Command("Check Validation", Menu.check_validate_menu_option),
                Command("Encrypt INPUT -> FILE", Menu.enc_inp2file),
                Command("Encrypt FILE -> FILE", Menu.enc_file2file),
                Command("Decrypt FILE -> CLIPBOARD", Menu.dec_file2clip),
                Command("Decrypt FILE -> FILE", Menu.dec_file2file),
                Command("Clear Clipboard", Menu.clear_clipboard),
                Command("Exit Program", Menu.close_program),
            )
            self.cmd_index = 0

            # Runs initial validation
            self.run_validation()
            # Runs main menu
            self.run_main_menu()

        # Call this to get a new encryptor class with the prompted password
        @staticmethod
        def get_encryptor():
            # Hashes the hidden input
            key_hash = hashlib.sha256(getpass.getpass("Gimme the sauce: ").encode('utf-8')).hexdigest()
            # Gets half of the hash to use as the key
            key = bytes(key_hash[:int(len(key_hash) / 2)], 'utf-8')
            clear()
            print()
            # Creates encryptor class
            return Encryptor(key)

        @staticmethod
        def file_navigator(header_message="SEARCH FILE"):
            script_pathlist = __file__.split("\\")
            script_filename = script_pathlist[-1]
            current_path = script_pathlist[0:len(script_pathlist) - 1]

            def get_path(pathlist):
                return "/".join(pathlist)

            def get_files(pathlist):
                return [".."] + [i for i in os.listdir(get_path(pathlist)) if i != script_filename]

            files = get_files(current_path)
            file_idx = 0

            while True:
                clear()
                print(header_message, "(ESC to cancel)")
                print("-----------")

                for idx in range(len(files)):
                    print((">" if idx == file_idx else " "), files[idx])

                print()
                print()
                print("This is where the cursor lives:")

                nextKey = msvcrt.getch()
                if os.name != "nt":
                    nextKey = stdscr.getch()

                print(nextKey)

                if (nextKey == b"P" and os.name == "nt") or (os.name != "nt" and nextKey == curses.KEY_DOWN):
                    file_idx += 1

                    if file_idx >= len(files):
                        file_idx = 0
                if (nextKey == b"H" and os.name == "nt") or (os.name != "nt" and nextKey == curses.KEY_UP):
                    file_idx -= 1

                    if file_idx < 0:
                        file_idx = len(files) - 1
                if (nextKey == b"\r" and os.name == "nt") or (os.name != "nt" and nextKey == curses.KEY_ENTER):
                    if files[file_idx] == "..":
                        current_path.pop(-1)
                        files = get_files(current_path)
                        file_idx = 0
                    elif os.path.isdir(get_path(current_path + [files[file_idx]])):
                        current_path.append(files[file_idx])
                        files = get_files(current_path)
                        file_idx = 0
                    else:
                        current_path.append(files[file_idx])
                        return get_path(current_path)
                if (nextKey == b"\x1b" and os.name == "nt") or (os.name != "nt" and nextKey == 27):
                    return -1

        def clear_clipboard(self):
            clear()

            pyperclip.copy(" ")
            print("clipboard cleared")
            print()

            press_any_key()

        def dec_file2clip(self):
            # Prompts user to select an existing file
            filename = self.file_navigator("DECRYPT FILE -> CLIPBOARD")
            clear()

            if filename != -1:
                # Decrypts and prints
                with open(filename, 'rb') as file:
                    cipherText = file.read()
                dec = Encryptor.decrypt(cipherText, self.encryptor.key)

                try:
                    pyperclip.copy(str(dec)[2:len(dec) + 2])
                    print("Your message has been copied")  # For actual message: str(dec))
                except Exception as e:
                    print("An Error Occurred while decrypting:")
                    print(e)

            press_any_key()

        def dec_file2file(self):
            # Prompts user to select an existing file
            filename = self.file_navigator("DECRYPT FILE -> FILE")
            clear()

            if filename != -1:
                self.encryptor.decrypt_file(filename)

                remove = input("Remove old file? (y/n)")

                if checkYes(remove):
                    os.remove(filename)
                    print("FILE REMOVED")
                else:
                    print("FILE NOT REMOVED")

            press_any_key()

        def enc_file2file(self):
            # Prompts user to select an existing file
            filename = self.file_navigator("ENCRYPT FILE -> FILE")
            clear()

            if filename != -1:
                self.encryptor.encrypt_file(filename)

                remove = input("Remove old file? (y/n)")

                if checkYes(remove):
                    os.remove(filename)
                    print("FILE REMOVED")
                else:
                    print("FILE NOT REMOVED")

            press_any_key()

        def enc_inp2file(self):
            clear()
            print("ENCRYPT INPUT -> FILE")
            print("----------------")

            # Prompts user to select a filename that does not exist yet
            valid = False
            while not valid:
                filename = input("Name your file: ")
                if os.path.exists(filename):
                    print("Error: File already exists!")
                else:
                    valid = True
                print()

            # Prompts user to enter desired message
            message = input("What message would you like to encrypt? ")

            # Save message to desired file in encrypted form
            with open(filename + ".enc", "wb") as file:
                enc = Encryptor.encrypt(message, self.encryptor.key)
                file.write(enc)

            press_any_key()

        def close_program(self):
            clear()
            if checkYes(input("Are you sure? ")):
                self.close = True

        def update_encryptor(self):
            clear()
            print("CHANGE DAT SAUCE")
            print("----------------")
            print()

            self.encryptor = self.get_encryptor()

        def run_main_menu(self):
            while True:
                clear()
                print("SELECT AN OPTION:")
                print("-----------")

                for idx in range(len(self.commands)):
                    print((">" if idx == self.cmd_index else " "), self.commands[idx].opt_string)

                print()
                print()
                print("This is where the cursor lives:")

                nextKey = msvcrt.getch()
                if os.name != "nt":
                    nextKey = stdscr.getch()

                if (nextKey == b"P" and os.name == "nt") or (os.name != "nt" and nextKey == curses.KEY_DOWN):
                    self.cmd_index += 1

                    if self.cmd_index >= len(self.commands):
                        self.cmd_index = 0
                if (nextKey == b"H" and os.name == "nt") or (os.name != "nt" and nextKey == curses.KEY_UP):
                    self.cmd_index -= 1

                    if self.cmd_index < 0:
                        self.cmd_index = len(self.commands) - 1
                if (nextKey == b"\r" and os.name == "nt") or (os.name != "nt" and nextKey == curses.KEY_ENTER):
                    self.commands[self.cmd_index].func(self)

                # End Program
                if self.close:
                    break

        # Call this right after getting the encrytor key to perform initial setup for the VALIDATE file
        def run_validation(self):
            clear()
            # Allows user to validate the password they entered by checking a validation file
            if not os.listdir().__contains__("VALIDATE"):
                # If Yes, creates file
                if checkYes(input("Would you like to create a validation file? ")):
                    self.create_validation_file(self.get_validation_message())
            else:
                self.check_validation()

            press_any_key()

        # Call this whenever you want to invoke a setup of the VALIDATE file from the menu
        def validation_setup(self):
            clear()
            print("VALIDATION SETUP")
            print("----------------")
            print()

            if not os.listdir().__contains__("VALIDATE"):
                # If Yes, creates file
                if checkYes(input("Would you like to create a validation file? ")):
                    self.create_validation_file(self.get_validation_message())

            else:
                with open("VALIDATE", "wb") as file:
                    file.truncate()
                    file.write(self.get_validation_message())

            press_any_key()

        # Asks for a password secret validation message and returns its encrypted form
        def get_validation_message(self):
            valid = False
            while not valid:
                # Asks for message
                validate_mess = getpass.getpass("Enter a message to validate: ")
                # Confirms the message
                if getpass.getpass("Confirm your message: ") == validate_mess:
                    valid = True
                else:
                    print()
                    print("Confirmation failed! Try again.")
                    print()
            return self.encryptor.encrypt(validate_mess, self.encryptor.key)

        # Creates a new validation file with the given message (message must be given encrypted)
        @staticmethod
        def create_validation_file(validate_mess):
            with open("VALIDATE", "wb") as file:
                file.write(validate_mess)

        # Executable as a menu option
        def check_validate_menu_option(self):
            clear()
            if os.listdir().__contains__("VALIDATE"):
                self.check_validation()
            else:
                print("Validation file not found. Please run setup")
            press_any_key()

        # Asks user if they would like to confirm validation. Goes through verification procedure
        def check_validation(self):
            # Asks user to try validation
            if checkYes(input("Would you like to validate? ")):
                # Reads encrypted file
                with open("VALIDATE", 'rb') as file:
                    cipherText = file.read()
                # Asks user for message check
                valid = False
                while not valid:
                    clear()
                    mess = input("Please enter the message in VALIDATE: ")
                    # Checks if message matches decrypted validation file
                    dec = self.encryptor.decrypt(cipherText, self.encryptor.key)
                    failed = False
                    try:
                        dec.decode("utf-8")
                    # Exception gets thrown if decryption done with wrong password
                    except Exception:
                        failed = True
                    if failed or mess != self.encryptor.decrypt(cipherText, self.encryptor.key).decode("utf-8"):
                        print(">>> Validation Failed!!!")
                        print()
                        if not checkYes(input("Would you like to re-enter your message? ")):
                            valid = True
                    else:
                        print(">>> Validation Successful!!!")
                        print()
                        valid = True

    MENU = Menu()

except Exception as e:
    print(e)
    traceback.print_exc()
    input()
