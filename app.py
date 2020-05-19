from os import urandom
from sqlite3 import connect
from base64 import urlsafe_b64encode, b64decode, b64encode
from hashlib import sha256
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

createTableQuery = """
    CREATE TABLE `{}` ({})
"""
checkTableExistsQuery = """
    SELECT name 
    FROM sqlite_master 
    WHERE type='table' and name='{}'
"""
checkConfigExistsQuery = """
    SELECT COUNT(*)
    FROM config
    WHERE key='{}'

"""
getConfigQuery = """
    SELECT value 
    FROM config 
    WHERE key='{}'
"""
insertConfigQuery = """
    INSERT INTO config 
    VALUES ('{}', '{}')
"""
getPasswordsQuery = """
    SELECT domain, user
    FROM password
"""
getPasswordQuery = """
    SELECT token, salt
    FROM password
    WHERE domain='{}' AND user='{}'
"""
insertPasswordQuery = """
    INSERT INTO password
    VALUES ('{}', '{}', '{}', '{}')
"""
editPasswordQuery = """
    UPDATE password
    SET token='{}', salt='{}'
    WHERE domain='{}' AND user='{}'
"""
removePasswordQuery = """
    DELETE FROM password
    WHERE domain='{}' AND user='{}'
"""


def hash(value):
    h = sha256()
    h.update(value.encode("utf-8"))
    return h.hexdigest()


def encrypt(value, password):
    salt = urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    f = Fernet(key)
    token = f.encrypt(value.encode("utf-8")).decode("utf-8")
    return token, b64encode(salt).decode("utf-8")


def decrypt(token, password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b64decode(salt.encode("utf-8")),
        iterations=100000,
        backend=default_backend(),
    )
    key = urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    f = Fernet(key)
    return f.decrypt(token.encode("utf-8")).decode("utf-8")


class App(object):
    def __init__(self):
        self.connection = connect("PasswordManager.db")
        self.cursor = self.connection.cursor()
        if not self.tableExists("config"):
            print("Creating config...")
            self.createTable("config", ("key", "value"))
        if not self.tableExists("password"):
            print("Creating passwords database...")
            self.createTable("password", ("domain", "user", "token", "salt"))

    def tableExists(self, name):
        self.cursor.execute(checkTableExistsQuery.format(name))
        return self.cursor.fetchone() is not None

    def createTable(self, name, columns):
        self.cursor.execute(
            createTableQuery.format(name, "'" + "','".join(columns) + "'")
        )
        self.connection.commit()

    def isMasterPassSet(self):
        self.cursor.execute(checkConfigExistsQuery.format("masterPass"))
        return bool(self.cursor.fetchone()[0])

    def login(self, masterPass):
        self.cursor.execute(getConfigQuery.format("masterPass"))
        if hash(masterPass) == self.cursor.fetchone()[0]:
            self.masterPass = masterPass
            return True
        return False

    def register(self, masterPass):
        self.cursor.execute(insertConfigQuery.format("masterPass", hash(masterPass)))
        self.masterPass = masterPass
        self.connection.commit()

    def addPassword(self, domain, user, password):
        token, salt = encrypt(password, self.masterPass)
        self.cursor.execute(insertPasswordQuery.format(domain, user, token, salt))
        self.connection.commit()

    def getPasswords(self):
        self.cursor.execute(getPasswordsQuery)
        return self.cursor.fetchall()

    def getPlainPassword(self, domain, user):
        self.cursor.execute(getPasswordQuery.format(domain, user))
        try:
            token, salt = self.cursor.fetchone()
            return decrypt(token, self.masterPass, salt)
        except TypeError:
            return None

    def editPassword(self, domain, user, password):
        token, salt = encrypt(password, self.masterPass)
        self.cursor.execute(editPasswordQuery.format(token, salt, domain, user))
        self.connection.commit()
        return bool(self.cursor.rowcount)

    def removePassword(self, domain, user):
        self.cursor.execute(removePasswordQuery.format(domain, user))
        self.connection.commit()
        return bool(self.cursor.rowcount)
