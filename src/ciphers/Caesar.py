from string import ascii_lowercase
from ciphers.Cipher import Cipher


class Caesar(Cipher):
    __valid_keys = set(range(26))
    __alphabet = set(ascii_lowercase)

    @classmethod
    def encrypt(cls, text, key):
        key = cls._check_key(key)
        return "".join(
            [
                chr((ord(char.lower()) + key - 97) % 26 + 97)
                if char.lower() in cls.__alphabet
                else char
                for char in text
            ]
        )

    @classmethod
    def decrypt(cls, text, key):
        key = cls._check_key(key)
        return "".join(
            [
                chr((ord(char.lower()) - key - 97) % 26 + 97)
                if char.lower() in cls.__alphabet
                else char
                for char in text
            ]
        )

    @classmethod
    def cryptanalysis(cls, encrypted, plain):
        for key in range(len(cls.__alphabet)):
            decrypted = cls.decrypt(encrypted, key)
            if decrypted.startswith(plain):
                return decrypted, key
        raise KeyError("Valid Key Not Found")

    @classmethod
    def crack(cls, text):
        return ''.join(
            [
                cls.decrypt(text, key) + "\n"
                for key in range(len(cls.__alphabet))
            ]
        )

    @classmethod
    def _check_key(cls, key):
        if int(key) in cls.__valid_keys:
            return int(key)
        else:
            raise KeyError(f"Wrong Key {key}.")
