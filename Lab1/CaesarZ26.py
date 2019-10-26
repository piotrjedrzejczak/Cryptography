from string import ascii_lowercase
from Cipher import Cipher

class CaesarZ26(Cipher):

    __charset = set(ascii_lowercase)

    @classmethod
    def encrypt(cls, text, key):
        encrypted = ''
        for char in text:
            if char in cls.__charset:
                encrypted += chr(((ord(char.lower())) + key - 97) % 26 + 97)
            else:
                encrypted += char
        return encrypted


    @classmethod
    def decrypt(cls, text, key):
        decrypted = ''
        for char in text:
            if char in cls.__charset:
                decrypted += chr((ord(char.lower()) - key - 97) % 26 + 97)
            else:
                decrypted += char
        return decrypted


    @classmethod
    def cryptoanalysis(cls, encrypted, plain):
        for key in range(0,26):
            if (decrypted := cls.decrypt(encrypted, key)).startswith(plain):
                return key, decrypted
        return -1, ''


    @classmethod
    def bruteforce(cls, text):
        results = ''
        for key in range(0,26):
            results += cls.decrypt(text, key) + '\n'
        return results