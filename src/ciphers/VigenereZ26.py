from src.ciphers.Cipher import Cipher
from src.ciphers.CaesarZ26 import CaesarZ26
from string import ascii_lowercase as ascii_low
from itertools import cycle
from collections import Counter
from math import fsum


class VigenereZ26(Cipher):

    __max_keyword_length = 1000
    __alphabet = {char: enum for enum, char in enumerate(ascii_low)}
    __english = {
        "a": 8.15,
        "b": 1.44,
        "c": 2.76,
        "d": 3.79,
        "e": 13.11,
        "f": 2.92,
        "g": 1.99,
        "h": 5.26,
        "i": 6.35,
        "j": 0.13,
        "k": 0.42,
        "l": 3.39,
        "m": 2.54,
        "n": 7.10,
        "o": 8.00,
        "p": 1.98,
        "q": 0.12,
        "r": 6.83,
        "s": 6.10,
        "t": 10.47,
        "u": 2.46,
        "v": 0.92,
        "w": 1.54,
        "x": 0.17,
        "y": 1.98,
        "z": 0.08,
    }

    @classmethod
    def encrypt(cls, text, key):
        key = cycle(key)
        return ''.join(
            [
                chr((ord(char) + cls.__alphabet[next(key)] - 97) % 26 + 97)
                for char in text
            ]
        )

    @classmethod
    def decrypt(cls, text, key):
        key = cycle(key)
        return ''.join(
            [
                chr((ord(char) - cls.__alphabet[next(key)] - 97) % 26 + 97)
                for char in text
            ]
        )

    @classmethod
    def cryptoanalysis(cls, text):
        kwlen = cls._keyword_length(text)
        if kwlen > 0:
            ceasar = CaesarZ26()
            # Rearrange the text into columns, one for each keyword letter
            rearranged = [
                ''.join(text[index::kwlen])
                for index in range(kwlen)
            ]
            keyword = ''
            for column in rearranged:
                distances = {}
                for char, enum in cls.__alphabet.items():
                    decrypted = ceasar.decrypt(column, enum)
                    frequencies = {
                        # Turn frequencies into percentage-like values
                        key: (value / len(column) * 100)
                        for key, value in Counter(decrypted).items()
                    }
                    distances[fsum(
                        [
                            abs(cls.__english[key] - frequencies.get(key, 0))
                            for key in cls.__english.keys()
                        ]
                    )] = char
                # Add best match to keyword
                keyword += distances[min(distances.keys())]
            return keyword
        else:
            raise ValueError('Key length cannot be 0.')

    @classmethod
    def bruteforce(cls):
        raise NotImplementedError

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
    def _keyword_length(cls, text):
        for kwlen in range(1, cls.__max_keyword_length):
            coincidences = []
            for m in range(kwlen + 1):
                subtext = ''.join(
                    [
                        letter for enum, letter in enumerate(text)
                        if enum % kwlen == m
                    ]
                )
                coincidences.append(cls._coincidence_index(subtext))
            if fsum(coincidences) / float(len(coincidences)) > 0.056:
                return kwlen
        return 0
