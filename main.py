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
    passwords = app.getPasswords()
    print()
    if passwords:
        print("\n".join("\t".join(password) for password in passwords))
    else:
        print("No passwords")
    print(commands)
    return input("Enter command: ")


def addPassword(app):
    clear()
    print("Add a new password:\n")
    domain = input("Domain: ")
    user = input("User: ")
    password = input("Password: ")
    app.addPassword(domain, user, password)
    print("Added password!")


def editPassword(app):
    clear()
    print("Edit a password:\n")
    domain = input("Domain: ")
    user = input("User: ")
    password = input("New Password: ")
    if app.editPassword(domain, user, password):
        print("Updated password!")
    else:
        print("Couldn't find the password!")


def removePassword(app):
    clear()
    print("Remove password:\n")
    domain = input("Domain: ")
    user = input("User: ")
    if app.removePassword(domain, user):
        print("Removed password!")
    else:
        print("Couldn't find the password!")


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


commandMapper = {
    "a": addPassword,
    "e": editPassword,
    "s": showPassword,
    "r": removePassword,
}


def main():
    app = App()
    if app.isMasterPassSet():
        print("Welcome back!")
        loggedIn = tryLogin(app)
        if loggedIn:
            print("Logged in!")
        else:
            print("Coudn't log you in!")
            return
    else:
        print("Hey there!")
        print("Let's setup your password manager!")
        tryRegister(app)
    input()
    command = ""
    while command != "q":
        command = getCommand(app)
        if command in commandMapper:
            commandMapper[command](app)
            input()


if __name__ == "__main__":
    main()
