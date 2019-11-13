from ciphers.Cipher import Cipher
from re import sub


class BitwiseZ26(Cipher):

    @classmethod
    def encrypt(cls, text, key):
        raise NotImplementedError

    @classmethod
    def decrypt(cls, text, key):
        raise NotImplementedError

    @classmethod
    def cryptoanalysis(cls, text):
        raise NotImplementedError

    @classmethod
    def bruteforce(cls, text):
        raise NotImplementedError

    @classmethod
    def _normalize_text(cls, text):
        return sub(r'[^a-zA-Z ]+', '', text).lower()
