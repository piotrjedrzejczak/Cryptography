from ciphers.Cipher import Cipher
from utils.const import ALPHABET_SET


class Caesar(Cipher):

    __VALID_KEYS = set(range(26))

    @classmethod
    def encrypt(cls, text, key):
        key = cls._check_key(key)
        return "".join(
            [
                chr((ord(char.lower()) + key - 97) % 26 + 97)
                if char.lower() in ALPHABET_SET
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
                if char.lower() in ALPHABET_SET
                else char
                for char in text
            ]
        )

    @classmethod
    def cryptanalysis(cls, encrypted, plain):
        for key in range(len(ALPHABET_SET)):
            decrypted = cls.decrypt(encrypted, key)
            if decrypted.startswith(plain):
                return decrypted, key
        raise KeyError("Valid Key Not Found")

    @classmethod
    def crack(cls, text):
        return ''.join(
            [
                cls.decrypt(text, key) + "\n"
                for key in range(len(ALPHABET_SET))
            ]
        )

    @classmethod
    def _check_key(cls, key):
        if int(key) in cls.__VALID_KEYS:
            return int(key)
        else:
            raise KeyError(f"Wrong Key {key}.")
