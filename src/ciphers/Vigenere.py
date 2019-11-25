from ciphers.Cipher import Cipher
from ciphers.Caesar import Caesar
from utils.const import ENGLISH_IOC, CHAR_ENUM_ALPHABET
from itertools import cycle
from collections import Counter
from math import fsum
from re import sub


class Vigenere(Cipher):

    __MAX_KEYSIZE = 1000

    @classmethod
    def encrypt(cls, text, key):
        key = cls._check_key(key)
        return "".join(
            [
                chr((ord(char.lower()) + CHAR_ENUM_ALPHABET[next(key)] - 97)
                    % 26 + 97)
                if char.lower() in CHAR_ENUM_ALPHABET
                else char
                for char in text
            ]
        )

    @classmethod
    def decrypt(cls, text, key):
        key = cls._check_key(key)
        return "".join(
            [
                chr((ord(char.lower()) - CHAR_ENUM_ALPHABET[next(key)] - 97)
                    % 26 + 97)
                if char.lower() in CHAR_ENUM_ALPHABET
                else char
                for char in text
            ]
        )

    @classmethod
    def cryptanalysis(cls, text):
        normalized = cls._normalize_text(text)
        keysize = cls._estimate_keysize(normalized)
        ceasar = Caesar()
        # Rearrange the text into columns, one for each keyword letter
        transposed = [
            "".join(normalized[index::keysize])
            for index in range(keysize)
        ]
        keyword = ""
        for column in transposed:
            distances = {}
            for char, enum in CHAR_ENUM_ALPHABET.items():
                decrypted = ceasar.decrypt(column, enum)
                frequencies = {
                    # Turn frequencies into percentage-like values
                    key: (value / len(column) * 100)
                    for key, value in Counter(decrypted).items()
                }
                distances[fsum(
                        [
                            abs(ENGLISH_IOC[key] - frequencies.get(key, 0))
                            for key in ENGLISH_IOC
                        ]
                    )
                ] = char
            # Add best match to keyword
            keyword += distances[min(distances)]
        return keyword

    @classmethod
    def crack(cls):
        raise NotImplementedError

    @classmethod
    def _check_key(cls, key):
        if type(key) != str:
            raise TypeError(f'Expected str, got {type(key)}')
        if len(key) == 0:
            raise ValueError('Key length cannot be 0')
        return cycle(''.join(
            [char for char in key if char in CHAR_ENUM_ALPHABET]
        ))

    @classmethod
    def _coincidence_index(cls, text):
        coincidence = fsum(
            [
                (frequency / len(text)) * ((frequency - 1) / (len(text) - 1))
                for frequency in Counter(text).values()
            ]
        )
        return coincidence

    @classmethod
    def _estimate_keysize(cls, text):
        for keysize in range(1, cls.__MAX_KEYSIZE):
            coincidences = []
            for m in range(keysize + 1):
                subtext = "".join(
                    [
                        letter for enum, letter in enumerate(text)
                        if enum % keysize == m
                    ]
                )
                coincidences.append(cls._coincidence_index(subtext))
            if fsum(coincidences) / float(len(coincidences)) > 0.056:
                return keysize
        raise KeyError(
            'Failed to find keyword length, try increasing the cap.\n'
            + f'Current cap: {cls.__MAX_KEYSIZE}'
        )

    @classmethod
    def _normalize_text(cls, text):
        return sub(r'[^a-zA-Z]+', '', text).lower()
