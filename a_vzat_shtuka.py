from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import hashlib
import pyperclip
import getpass
import traceback
import random
from abc import abstractmethod
import signal
import sys
from typing import Optional

if os.name == "nt":
    import msvcrt
else:
    import curses
    stdscr = curses.initscr()
    curses.cbreak(False)


class Encryptor:
    """Functionality to encrypt and decrypt messages using a specified key"""
    def __init__(self, key):
        self.key = key

    @staticmethod
    def pad(s):
        mess = s
        if not type(mess) == bytes:
            mess = bytes(mess, 'utf-8')
        return mess + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key_size=256):
        message = Encryptor.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as file:
            plaintext = file.read()
        enc = self.encrypt(plaintext)
        with open(file_name + ".enc", 'wb') as file:
            file.write(enc)

    def decrypt(self, cipherText):
        iv = cipherText[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(cipherText[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as file:
            cipherText = file.read()
        dec = self.decrypt(cipherText)
        with open(file_name[:-4], 'wb') as file:
            file.write(dec)


class Command:
    def __init__(self, opt_string, func):
        self.func = func
        self.opt_string = opt_string


class Menu:
    """Uses encryptor to provide a convenient interface for a set of encryption
    and decryption features for files and input. This abstract class defines
    methods which need to be implemented by an arbitrary UI library. UI is
    expected to be organized into a stack of content blocks. The latest
    called content block is the one taking user input."""
    def __init__(self):
        # Creates encryptor
        self.encryptor = None

        # Set flag to true to close program
        self.close = False

        # Creates commands
        self.commands: tuple[Command, ...] = (
            Command("Change the Sauce", Menu.update_encryptor),
            Command("Encrypt INPUT -> FILE", Menu.enc_inp2file),
            Command("Encrypt FILE -> FILE", Menu.enc_file2file),
            Command("Decrypt FILE -> CLIPBOARD", Menu.dec_file2clip),
            Command("Decrypt FILE -> FILE", Menu.dec_file2file),
            Command("Generate Password", Menu.generate_password),
            Command("Clear Clipboard", Menu.clear_clipboard),
            Command("Exit Program", Menu.close_program),
        )
        self.cmd_index = 0

    def launch(self):
        """Start the application"""
        def signal_handler(sig, frame):
            MENU.destroy()
            sys.exit(0)
        signal.signal(signal.SIGINT, signal_handler)

        # Runs main menu
        try:
            self.run_main_menu()
        except Exception as e:
            MENU.destroy()
            print(e)
            traceback.print_exc()

    def get_encryptor_with_prompted_key(self) -> Optional[Encryptor]:
        """Prompt user for a new password and update encryptor"""
        s = self.content_get_confirmed_message("Gimme the sauce:",
                                               "Confirm the sauce:", True)
        if s is None: return None
        return self.get_encryptor(s)

    # Call this to get a new encryptor class with the prompted password
    @staticmethod
    def get_encryptor(key: str) -> Encryptor:
        """Return encryptor for the given key. Hashes the key"""
        # Hashes the hidden input
        key_hash = hashlib.sha256(key.encode('utf-8')).hexdigest()
        # Gets half of the hash to use as the key
        key = bytes(key_hash[:int(len(key_hash) / 2)], 'utf-8')
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

            if os.name == "nt":
                nextKey = msvcrt.getch()
            else:
                nextKey = stdscr.getch()

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

    def generate_password(self):
        clear()
        valid = False
        while not valid:
            length = input("Password Length: ")
            try:
                length = int(length)
                valid = True
            except Exception:
                print("Enter a valid number")

        clear()
        letters = "abcdefghijklmnopqrstuvwxyz"
        caps = letters.upper()
        nums = "1234567890"
        symbols = "!@#$%^&*()-=_+,.<>"
        all_text = letters + caps + nums + symbols
        pyperclip.copy("".join([random.choice(all_text) for _ in range(length)]))
        print("Your password has been copied!")
        press_any_key()

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
            dec = self.encryptor.decrypt(cipherText)

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
            enc = self.encryptor.encrypt(message)
            file.write(enc)

        press_any_key()

    def close_program(self):
        clear()
        if checkYes(input("Are you sure? ")):
            self.close = True

    def update_encryptor(self):
        self.clear_screen()
        self.content_text_block("COOK NEW SAUCE")
        self.content_divider()
        new_encryptor = self.get_encryptor_with_prompted_key()
        if new_encryptor is None:
            self.content_text_block("Cooking operation has been canceled.")
            self.content_press_any_key()
        else:
            self.encryptor = new_encryptor
            self.content_text_block("Cooked new sauce successfully!")
            self.content_press_any_key()

    def run_main_menu(self):
        """Runs command selection loop"""
        self.init()

        while True:
            self.clear_screen()
            self.encryptor = self.get_encryptor_with_prompted_key()
            if self.encryptor is not None:
                break

        while True:
            self.clear_screen()
            self.content_text_block("SELECT AN OPTION:")
            self.content_divider()
            idx = self.content_get_index_from_list(
                [c.opt_string for c in self.commands]
            )
            if idx is not None: self.commands[idx].func(self)

            # End Program
            if self.close:
                break

        self.destroy()

    # Call this right after getting the encrytor key to perform initial setup for the VALIDATE file
    def run_validation(self):
        self.clear_screen()
        # Allows user to validate the password they entered by checking a validation file
        if not os.listdir().__contains__("VALIDATE"):
            # If Yes, creates file
            #if checkYes(input("Would you like to create a validation file? ")):
            if self.content_get_bool_from_user("Would you like to create a validation file?"):
                self.create_validation_file(self.get_validation_message())
        else:
            self.check_validation()

        self.content_press_any_key()

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
        return self.encryptor.encrypt(self.content_get_confirmed_message("Enter a message to validate:", "Confirm your message:"))
        # valid = False
        # while not valid:
        #     # Asks for message
        #     validate_mess = getpass.getpass("Enter a message to validate: ")
        #     # Confirms the message
        #     if getpass.getpass("Confirm your message: ") == validate_mess:
        #         valid = True
        #     else:
        #         print()
        #         print("Confirmation failed! Try again.")
        #         print()
        # return self.encryptor.encrypt(validate_mess)

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
                dec = self.encryptor.decrypt(cipherText)
                failed = False
                try:
                    dec.decode("utf-8")
                # Exception gets thrown if decryption done with wrong password
                except Exception:
                    failed = True
                if failed or mess != self.encryptor.decrypt(cipherText).decode("utf-8"):
                    print(">>> Validation Failed!!!")
                    print()
                    if not checkYes(input("Would you like to re-enter your message? ")):
                        valid = True
                else:
                    print(">>> Validation Successful!!!")
                    print()
                    valid = True

    @abstractmethod
    def init(self):
        """Run any UI initialization"""

    @abstractmethod
    def destroy(self):
        """Run any UI exit procedures"""

    @abstractmethod
    def clear_screen(self):
        """Clear the screen of all content blocks"""

    @abstractmethod
    def content_get_bool_from_user(self, prompt: str) -> Optional[bool]:
        """Content block prompting the user with the given prompt and return a yes (true) or
        no (false) answer. User may cancel this operation in which case None should be returned"""

    @abstractmethod
    def content_press_any_key(self, text="Press any key to continue..."):
        """Content block prompting the user to press any key to continue. Block until user does so"""

    @abstractmethod
    def content_text_block(self, text: str):
        """Content block displaying text"""

    @abstractmethod
    def content_divider(self):
        """Content block displaying a horizontal line divider"""

    @abstractmethod
    def content_get_str_from_user(self, prompt: str, hide: bool) -> Optional[str]:
        """Prompt the user with the given prompt and return user's input string.
        Hide user's writing if hide=True. User may cancel this operation in
        which case None should be returned"""

    def pop_contents(self, n: int):
        """Clear the latest n blocks"""
        for _ in range(n):
            self.pop_content()

    @abstractmethod
    def pop_content(self):
        """Clear the latest content block"""

    def content_get_confirmed_message(self, prompt: str, confirmation_prompt: str, hide=True) -> Optional[str]:
        """Content block prompting the user to enter a message and confirm it.
        Prompt repeatedly until confirmation matches entered message. Return the final
        message. If hide=True, the user's input should be hidden. User may cancel this operation in
        which case None should be returned"""
        canceled = False
        while True:
            m1 = self.content_get_str_from_user(prompt, hide)
            if m1 is None:
                canceled = True
                break
            m2 = self.content_get_str_from_user(confirmation_prompt, hide)
            if m2 is None:
                canceled = True
                break
            if m1 == m2:
                break
            self.content_text_block("Messages don't match!")
            self.content_press_any_key()
            self.pop_contents(4)

        if canceled: return None
        return m1

    @abstractmethod
    def content_get_index_from_list(self, options: list[str], max_n: Optional[int] = None) -> Optional[int]:
        """Given a list of options, provide a content block which allows selecting
        one of the options. Return the index of the selected option. User may cancel this operation in
        which case None should be returned"""


class CursesMenu(Menu):
    def __init__(self):
        super().__init__()
        self.stdscr = None
        self.pad = None
        self.block_stack: list[int] = []  # list of y coordinates of current blocks

    def commit_block(self):
        """After writing a new content block, call this to record the blocks coordinate to the stack
        and move the cursor to the next line"""
        content_end = self.pad.getyx()[0]
        self.block_stack.append(content_end)
        self.pad.move(content_end + 1, 0)
        self.refresh_pad()

    def is_enter(self, k: int):
        return k in [curses.KEY_ENTER, 10, 13]

    def init(self):
        self.stdscr = curses.initscr()
        self.pad = curses.newpad(1000, 1000)
        curses.start_color()
        curses.noecho()
        curses.cbreak()
        #curses.curs_set(0)
        self.stdscr.keypad(True)
        self.pad.keypad(True)
        self.stdscr.clear()
        self.pad.clear()

        # self.content_get_str_from_user("Gimme text bruh?", False)
        # self.pad.getch()
        # self.content_divider()
        # self.pad.getch()
        # self.content_press_any_key()
        # self.pop_contents(2)
        # self.refresh_pad()
        # self.pad.getch()
        # self.content_get_bool_from_user("yes or no hmmmmm?")
        # self.pad.getch()

    def destroy(self):
        curses.echo()
        self.stdscr.keypad(False)
        self.pad.keypad(False)
        curses.nocbreak()
        curses.curs_set(1)
        curses.endwin()

    def erase_coordinate(self, x: int, y: int, do_erase=True):
        """Clear a single terminal coordinate"""
        self.pad.addstr(y, x, " ", curses.A_NORMAL)
        if do_erase: self.refresh_pad()

    def erase_coordinates(self, top_left_xy: tuple[int, int], bottom_right_xy: tuple[int, int]):
        """Inclusively clear all cells in a rectangle from top left to bottom right"""
        for y in range(top_left_xy[1], bottom_right_xy[1] + 1):
            for x in range(top_left_xy[0], bottom_right_xy[0] + 1):
                self.erase_coordinate(x, y, False)
        self.refresh_pad()

    def erase_rows(self, start_inclusive: int, stop_inclusive: int):
        """Erase a range of rows"""
        self.erase_coordinates((0, start_inclusive), (self.stdscr.getmaxyx()[1], stop_inclusive))

    def refresh_pad(self):
        """Refreshes pad using topleft corner and full screen size"""
        self.pad.refresh(0, 0, 0, 0, self.stdscr.getmaxyx()[0] - 1, self.stdscr.getmaxyx()[1] - 1)

    def clear_screen(self):
        self.block_stack = []
        self.pad.clear()
        self.pad.move(0, 0)
        self.refresh_pad()

    def content_get_bool_from_user(self, prompt: str) -> Optional[bool]:
        def draw_line(is_yes: bool):
            self.pad.addstr(prompt + " ")
            self.pad.addstr("YES", curses.A_REVERSE if is_yes else curses.A_NORMAL)
            self.pad.addstr(" ")
            self.pad.addstr("NO", curses.A_REVERSE if not is_yes else curses.A_NORMAL)
            self.commit_block()

        is_yes = True
        cancelled = False
        while True:
            draw_line(is_yes)
            k = self.pad.getch()
            if self.is_enter(k):
                break
            elif k == curses.KEY_RIGHT or k == curses.KEY_LEFT:
                is_yes = not is_yes
            elif k == 27:
                cancelled = True
                break
            self.pop_content()

        if cancelled: return None
        return is_yes

    def content_press_any_key(self, text="Press any key to continue..."):
        self.pad.addstr(text)
        self.refresh_pad()
        while True:
            if self.pad.getch() <= 260:
                break
        self.commit_block()

    def content_text_block(self, text: str, flags=curses.A_NORMAL):
        self.pad.addstr(text, flags)
        self.refresh_pad()
        self.commit_block()

    def content_divider(self):
        self.pad.addstr("-" * self.stdscr.getmaxyx()[1])
        self.refresh_pad()
        self.commit_block()

    def content_get_str_from_user(self, prompt: str, hide: bool) -> Optional[str]:
        s = ""
        self.pad.addstr(prompt + " ")
        self.refresh_pad()
        cancelled = False
        while True:
            k = self.pad.getch()
            if self.is_enter(k):
                break
            elif k == 127:
                if len(s) > 0:
                    s = s[:-1]
                    shift_back_pos = self.pad.getyx()[1] - 1, self.pad.getyx()[0]
                    self.erase_coordinate(*shift_back_pos)
                    self.pad.move(shift_back_pos[1], shift_back_pos[0])
            elif k == 27:
                cancelled = True
                break
            else:
                s += chr(k)
                if not hide:
                    self.pad.addstr(chr(k))
                    self.refresh_pad()
        self.commit_block()
        if cancelled: return None
        return s

    def pop_content(self):
        if len(self.block_stack) > 1:
            self.erase_rows(self.block_stack[-2] + 1, self.block_stack[-1])
            self.block_stack.pop(-1)
            self.pad.move(self.block_stack[-1] + 1, 0)
        else:
            self.clear_screen()

    def content_get_index_from_list(self, options: list[str], max_n: Optional[int] = None) -> Optional[int]:
        i = 0
        display_start_i = 0
        length = len(options) if max_n is None else min(len(options), max_n)
        cancelled = False

        while True:
            for o in range(length):
                idx = display_start_i + o if length < len(options) else o

                self.content_text_block((">" if idx == i else " ") + options[idx],
                                        curses.A_NORMAL if idx != i else curses.A_REVERSE)

            k = self.pad.getch()
            if self.is_enter(k):
                break
            elif k == curses.KEY_DOWN:
                i = (i + 1) % len(options)
            elif k == curses.KEY_UP:
                i = (i - 1) % len(options)
            elif k == 27:
                cancelled = True
                break

            if length < len(options):
                if i < display_start_i:
                    display_start_i = i
                elif i >= display_start_i + length:
                    display_start_i += i - (display_start_i + length - 1)

            self.pop_contents(length)

        if cancelled: return None
        return i

        # for idx in range(len(self.commands)):
        #     print((">" if idx == self.cmd_index else " "), self.commands[idx].opt_string)
        #
        # print()
        # print()
        # print("This is where the cursor lives:")
        #
        # if os.name == "nt":
        #     nextKey = msvcrt.getch()
        # else:
        #     nextKey = stdscr.getch()
        #
        # if (nextKey == b"P" and os.name == "nt") or (os.name != "nt" and nextKey == curses.KEY_DOWN):
        #     self.cmd_index += 1
        #
        #     if self.cmd_index >= len(self.commands):
        #         self.cmd_index = 0
        # if (nextKey == b"H" and os.name == "nt") or (os.name != "nt" and nextKey == curses.KEY_UP):
        #     self.cmd_index -= 1
        #
        #     if self.cmd_index < 0:
        #         self.cmd_index = len(self.commands) - 1
        # if (nextKey == b"\r" and os.name == "nt") or (os.name != "nt" and nextKey == curses.KEY_ENTER):
        #     self.commands[self.cmd_index].func(self)
        #
        # # TODO: Fix


MENU = CursesMenu()
MENU.launch()
