try:
    from Crypto import Random
    from Crypto.Cipher import AES
    import os
    import os.path
    from os import listdir
    from os.path import isfile, join
    import hashlib
    import pyperclip

    clear = lambda: os.system('cls')


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


    key_hash = hashlib.sha256(input("Gimme the sauce:").encode('utf-8')).hexdigest()
    key = bytes(key_hash[:int(len(key_hash) / 2)], 'utf-8')
    print()

    encryptor = Encryptor(key)

    while True:
        print("Choose an option: ")
        print("   1. Encrypt input to file")
        print("   2. Encrypt input print")
        print("   4. Encrypt file to file")
        print("   5. Decrypt file print")
        print("   6. Decrypt file to file")
        print("   8. List files")
        print("   9. List files with string")
        print("   0. Clear clipboard")
        print("   7. Exit")
        print()
        choice = input("select an option: ")
        print()

        if choice == "1":
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
                enc = Encryptor.encrypt(message, encryptor.key)
                file.write(enc)

        elif choice == "8":
            # List file names in directory
            [print("|-- ", file) for file in os.listdir()]

        elif choice == "9":
            string = input("Search for files including: ")

            print()
            [print("|-- ", file) for file in os.listdir() if string in file]

        elif choice == "0":
            pyperclip.copy(" ")
            print("clipboard cleared")

        elif choice == "2":
            # Prints the encrypted version of a desired message
            message = input("What message would you like to encrypt? ")

            print(Encryptor.encrypt(message, encryptor.key))

        elif choice == "3":
            print("Read the list dumb ass. '3' isn't an option")

        elif choice == "4":
            # Prompts user to select an existing file
            valid = False
            while not valid:
                filename = input("What file are you finna encrypt? ")
                if not os.path.exists(filename):
                    print("Error: File doesn't exist!")
                else:
                    valid = True
                print()

            encryptor.encrypt_file(filename)

            remove = input("Remove old file? (y/n)")

            if remove == "y":
                os.remove(filename)
                print("FILE REMOVED")
            else:
                print("FILE NOT REMOVED")

        elif choice == "5":
            # Prompts user to select an existing file
            valid = False
            while not valid:
                filename = input("What file are you finna decrypt? ")
                if not os.path.exists(filename):
                    print("Error: File doesn't exist!")
                else:
                    valid = True
                print()

            # Decrypts and prints
            with open(filename, 'rb') as file:
                cipherText = file.read()
            dec = Encryptor.decrypt(cipherText, encryptor.key)

            print("Your message:")
            print("has been copied")  # str(dec))
            try:
                pyperclip.copy(str(dec)[2:len(dec) + 2])
            except Exception as e:
                print(e)

        elif choice == "6":
            # Prompts user to select an existing file
            valid = False
            while not valid:
                filename = input("What file are you finna decrypt? ")
                if not os.path.exists(filename):
                    print("Error: File doesn't exist!")
                else:
                    valid = True
                print()

            encryptor.decrypt_file(filename)

            remove = input("Remove old file? (y/n)")

            if remove == "y":
                os.remove(filename)
                print("FILE REMOVED")
            else:
                print("FILE NOT REMOVED")

        elif choice == "7":
            break

        print()
        input("press enter to continue")
        clear()

    print()
    input("press enter to exit")
    print()

except Exception as e:
    print(e)
    input()
