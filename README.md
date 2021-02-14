# Password Manager

A **secure** menu driven cli password manager in **python**.

## Demo

![Demo](/demo.svg)

## Usage

```shell
pip install -r requirements.txt
python main.py
```

## Implementation

### Libraries

- **sqlite3**: To storie data with SQL interface.
- **hashlib**: To implement sha256 hash.
- **cryptography**: To implement encryption and decryption of passwords.

### Security

- The master password is stored using a sha256 hash.
- All the account passwords use a combination of master password and randomly generated salt as the encryption key.
