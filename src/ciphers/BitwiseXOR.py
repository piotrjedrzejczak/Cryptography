from ciphers.Cipher import Cipher
from re import sub


class BitwiseXOR(Cipher):

    @classmethod
    def encrypt(cls, text, key):
        text = cls._normalize_text(text)
        chunks = cls._chunk(text, len(key))
        for chunk in chunks:
            [bin(ord(char))]
    @classmethod
    def decrypt(cls, text, key):
        raise NotImplementedError

    @classmethod
    def cryptanalysis(cls, text):
        raise NotImplementedError

    @classmethod
    def crack(cls, text):
        raise NotImplementedError

    @classmethod
    def _normalize_text(cls, text):
        return sub(r'[^a-zA-Z ]+', '', text).strip().lower()

    @classmethod
    def _chunk(cls, text, size):
        for index in range(0, len(text), size):
            yield text[index:index+size]
