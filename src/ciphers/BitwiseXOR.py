from ciphers.Cipher import Cipher
from collections import Counter
from utils.const import ENGLISH_IOC


class BitwiseXOR(Cipher):

    @classmethod
    def encrypt(cls, text, key):
        text = text.encode('ascii')
        key = key.encode('ascii')
        return cls._hexify_encryption_matrix(
            [
                [
                    char ^ key[enum]
                    for enum, char in enumerate(text[shift:shift+len(key)])
                ]
                for shift in range(0, len(text), len(key))
            ]
        )

    @classmethod
    def decrypt(cls, hexified_text, key):
        key = key.encode('ascii')
        return ''.join(
            [
                chr(byte ^ key[enum])
                for row in hexified_text.split('\n')
                for enum, byte in enumerate(cls._hex_to_bytes(row))
            ]
        )

    @classmethod
    def cryptanalysis(cls, cryptogram):
        keyword = ''
        keysize = int(cryptogram.find('\n') / 2)
        cryptobytes = cls._hex_to_bytes(cryptogram.replace('\n', ''))
        for column in range(keysize):
            vector = cryptobytes[column::keysize]
            distances = {}
            for char in range(123):
                decrypted = [chr(vector[i] ^ char) for i in range(len(vector))]
                frequencies = {
                    # Turn frequencies into percentage-like values
                    key: value / len(vector) * 100
                    for key, value in Counter(decrypted).items()
                }
                distances[sum(
                        [
                            abs(ENGLISH_IOC[key] - frequencies.get(key, 0))
                            for key in ENGLISH_IOC
                        ]
                    )
                ] = chr(char)
            # Add best match to keyword
            keyword += distances[min(distances)]
        return keyword

    @classmethod
    def crack(cls, text):
        raise NotImplementedError

    @classmethod
    def _hex_to_bytes(cls, h):
        return bytes(
            int(h[i:i+2], 16)
            for i in range(0, len(h), 2)
        )

    @classmethod
    def _bytes_to_hex(cls, b):
        return ''.join('%02x' % i for i in b)

    @classmethod
    def _int_to_hex(cls, num):
        num = hex(num).replace('0x', '').replace('L', '')
        if len(num) % 2 == 1:
            num = '0' + num
        return num

    @classmethod
    def _hexify_encryption_matrix(cls, text_matrix):
        return ''.join(
                [
                    ''.join([cls._int_to_hex(byte) for byte in row]) + '\n'
                    for row in text_matrix
                ]
            )
