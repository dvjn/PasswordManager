import os
from getpass import getpass

from app import App


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def tryLogin(app):
    for i in range(3):
        masterPass = getpass("Enter master password: ")
        if app.login(masterPass):
            return True
        print("Incorrect password!")
    return False


def tryRegister(app):
    while True:
        masterPass = getpass("Create a master password: ")
        if masterPass == getpass("Enter master password again: "):
            app.register(masterPass)
            return True
        print("Passwords did not match!")


def addPassword(app):
    clear()
    print("Add a new password:\n")
    domain = input("Domain: ")
    user = input("User: ")
    while True:
        password = getpass("Password: ")
        if password == getpass("Retype Password: "):
            app.addPassword(domain, user, password)
            print("Added password!")
            return
        print("Passwords did not match!")


def showPassword(app):
    clear()
    print("Show password:\n")
    domain = input("Domain: ")
    user = input("User: ")
    password = app.getPlainPassword(domain, user)
    if password is not None:
        print("Password: " + password)
    else:
        print("Couldn't find the password!")


def editPassword(app):
    clear()
    print("Edit a password:\n")
    domain = input("Domain: ")
    user = input("User: ")
    while True:
        password = getpass("New Password: ")
        if password == getpass("Retype New Password: "):
            if app.editPassword(domain, user, password):
                print("Updated password!")
            else:
                print("Couldn't find the password!")
            return
        print("Passwords did not match!")


def removePassword(app):
    clear()
    print("Remove password:\n")
    domain = input("Domain: ")
    user = input("User: ")
    if app.removePassword(domain, user):
        print("Removed password!")
    else:
        print("Couldn't find the password!")


commandMap = {
    "a": addPassword,
    "s": showPassword,
    "e": editPassword,
    "r": removePassword,
}


commands = """
Commands:
    a) Add password
    s) Show password
    e) Edit password
    r) Remove Password
    q) Quit
"""


def getCommand(app):
    clear()
    print("Password Manager")
    print()
    passwords = app.getPasswords()
    if passwords:
        print("\n".join("\t".join(password) for password in passwords))
    else:
        print("No passwords")
    print(commands)
    return input("Enter command: ")


def waitForReturn():
    input("Press enter to continue... ")


def main():
    try:
        clear()
        print("Password Manager")
        print()
        app = App()
        if app.isMasterPassSet():
            print("Welcome back!")
            if tryLogin(app):
                print("Logged in!")
            else:
                print("Couldn't log you in!")
                return
        else:
            print("Hey there!")
            print("Let's setup your password manager!")
            tryRegister(app)
        waitForReturn()
        command = ""
        while command != "q":
            command = getCommand(app)
            if command in commandMap:
                commandMap[command](app)
                waitForReturn()
    except KeyboardInterrupt:
        print("\nExiting...")


if __name__ == "__main__":
    main()
