from ciphers.Cipher import Cipher
from utils.utils import xor
from random import randrange


class ECB(Cipher):

    @classmethod
    def encrypt(cls, bmp):
        key = bytearray([randrange(255) for byte in range(128)])
        offset = sum([byte for byte in bmp[10:14]])  # Pixel array offset
        file_header = bytearray(bmp[:offset])
        epa = bytearray()  # Encrypted pixel array
        for block in range(offset, len(bmp), len(key)):
            epa.extend(xor(key, bmp[block:block+len(key)]))
        return file_header + epa  # Header + Pixel Array = Valid BMP File

    @classmethod
    def decrypt(cls):
        raise NotImplementedError

    @classmethod
    def cryptanalysis(cls):
        raise NotImplementedError

    @classmethod
    def crack(cls):
        raise NotImplementedError
