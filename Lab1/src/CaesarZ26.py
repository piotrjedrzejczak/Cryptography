from string import ascii_lowercase
from src.Cipher import Cipher

class CaesarZ26(Cipher):
    __valid_keys = set(range(0,26))
    __charset = set(ascii_lowercase)

    @classmethod
    def encrypt(cls, text, key):
        if key in cls.__valid_keys:
            encrypted = ''
            for char in text:
                if char in cls.__charset:
                    encrypted += chr(((ord(char.lower())) + key - 97) % 26 + 97)
                else:
                    encrypted += char
            return encrypted
        else:
            raise KeyError(f'Invalid Key {key}')
            

    @classmethod
    def decrypt(cls, text, key):
        if key in cls.__valid_keys:
            decrypted = ''
            for char in text:
                if char in cls.__charset:
                    decrypted += chr((ord(char.lower()) - key - 97) % 26 + 97)
                else:
                    decrypted += char
            return decrypted
        else:
            raise KeyError(f'Invalid Key {key}')
        

    @classmethod
    def cryptoanalysis(cls, encrypted, plain):
        for key in range(0,26):
            if (decrypted := cls.decrypt(encrypted, key)).startswith(plain):
                return key, decrypted
        raise KeyError('Valid Key Not Found')


    @classmethod
    def bruteforce(cls, text):
        results = ''
        for key in range(0,26):
            results += cls.decrypt(text, key) + '\n'
        return results