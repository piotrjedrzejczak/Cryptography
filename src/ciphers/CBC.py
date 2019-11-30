from ciphers.Cipher import Cipher
from random import randrange
from utils.utils import xor
from struct import unpack


class CBC(Cipher):

    _KEYSIZE = 64
    _IV = bytearray([randrange(256) for byte in range(_KEYSIZE)])

    @classmethod
    def encrypt(cls, bmp):
        key = bytearray([randrange(256) for byte in range(cls._KEYSIZE)])
        offset = unpack('I', bmp[10:14])[0]  # Pixel Array Offset
        file_header = bytearray(bmp[:offset])
        epa = bytearray()  # Encrypted pixel array
        for block in range(offset, len(bmp), len(key)):
            ivxorblock = xor(cls._IV, bmp[block:block+len(key)])
            encryption = cls._permutate(ivxorblock, key, offset)
            cls._IV = encryption
            epa.extend(encryption)
        return file_header + epa  # Header + Pixel Array = Valid BMP File

    @classmethod
    def _permutate(cls, v1, v2, coeff):
        return bytearray(
            [
                (((byte1 ^ byte2) * coeff) % 256) ^ byte1
                for byte1, byte2 in zip(v1, v2)
            ]
        )

    @classmethod
    def decrypt(cls):
        raise NotImplementedError

    @classmethod
    def cryptanalysis(cls):
        raise NotImplementedError

    @classmethod
    def crack(cls):
        raise NotImplementedError
