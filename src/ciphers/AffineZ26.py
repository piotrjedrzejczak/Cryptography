from string import ascii_lowercase
from src.ciphers.Cipher import Cipher


class AffineZ26(Cipher):
    __alphabet = dict(zip(ascii_lowercase, range(26)))
    __inverted_alphabet = {code: letter for letter, code in __alphabet.items()}
    __inverses = {
        1: 1,
        3: 9,
        5: 21,
        7: 15,
        9: 3,
        11: 19,
        15: 7,
        17: 23,
        19: 11,
        21: 5,
        23: 17,
        25: 25,
    }

    @classmethod
    def encrypt(cls, text, keys):
        key1, key2 = cls._check_keys(keys)
        return ''.join(
            [
                cls.__inverted_alphabet[
                    (key1 * cls.__alphabet[char.lower()] + key2)
                    % len(cls.__alphabet)
                ]
                if char in cls.__alphabet.keys()
                else char
                for char in text
            ]
        )

    @classmethod
    def decrypt(cls, text, keys):
        key1, key2 = cls._check_keys(keys)
        return ''.join(
            [
                cls.__inverted_alphabet[
                    (cls.__inverses[key1])
                    * (cls.__alphabet[char.lower()] - key2)
                    % len(cls.__alphabet)
                ]
                if char in cls.__alphabet.keys()
                else char
                for char in text
            ]
        )

    @classmethod
    def cryptoanalysis(cls, encrypted, plain):
        for key1 in cls.__inverses.keys():
            for key2 in cls.__inverted_alphabet.keys():
                decrypted = cls.decrypt(encrypted, f"{key1} {key2}")
                if decrypted.startswith(plain):
                    return decrypted, f"{key1} {key2}"
        raise KeyError("Valid Keys Not Found")

    @classmethod
    def bruteforce(cls, text):
        return ''.join(
            [
                cls.decrypt(text, f'{key1} {key2}') + "\n"
                for key2 in cls.__inverted_alphabet.keys()
                for key1 in cls.__inverses.keys()
            ]
        )

    @classmethod
    def _check_keys(cls, keys):
        try:
            key1, key2 = [int(key) for key in keys.strip().split(" ")]
            if key1 not in cls.__inverses:
                raise KeyError(
                    f"First Key is Invalid: {key1}"
                    + f"Valid Keys: {cls.__inverses.keys()}"
                )
            if key2 not in cls.__inverted_alphabet:
                raise KeyError(
                    f"Second Key is Invalid: {key2}"
                    + f"Valid Keys: {cls.__inverted_alphabet.keys()}"
                )
            return key1, key2
        except ValueError:
            raise ValueError(
                f"Not Parsable Keys: {keys}\n"
                + "Expected Format: FirstKey[SPACE]SecondKey"
            )

