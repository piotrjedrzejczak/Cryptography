from ciphers.Cipher import Cipher
from utils.const import CHAR_ENUM_ALPHABET, ENUM_CHAR_ALPHABET, Z26_INVERSES


class Affine(Cipher):

    @classmethod
    def encrypt(cls, text, keys):
        key1, key2 = cls._check_keys(keys)
        return ''.join(
            [
                ENUM_CHAR_ALPHABET[
                    (key1 * CHAR_ENUM_ALPHABET[char.lower()] + key2)
                    % len(CHAR_ENUM_ALPHABET)
                ]
                if char.lower() in CHAR_ENUM_ALPHABET
                else char
                for char in text
            ]
        )

    @classmethod
    def decrypt(cls, text, keys):
        key1, key2 = cls._check_keys(keys)
        return ''.join(
            [
                ENUM_CHAR_ALPHABET[
                    (Z26_INVERSES[key1])
                    * (CHAR_ENUM_ALPHABET[char.lower()] - key2)
                    % len(CHAR_ENUM_ALPHABET)
                ]
                if char.lower() in CHAR_ENUM_ALPHABET
                else char
                for char in text
            ]
        )

    @classmethod
    def cryptoanalysis(cls, encrypted, plain):
        for key1 in Z26_INVERSES:
            for key2 in ENUM_CHAR_ALPHABET:
                decrypted = cls.decrypt(encrypted, f"{key1} {key2}")
                if decrypted.startswith(plain):
                    return decrypted, f"{key1} {key2}"
        raise KeyError("Valid Keys Not Found")

    @classmethod
    def crack(cls, text):
        return ''.join(
            [
                cls.decrypt(text, f'{key1} {key2}') + "\n"
                for key2 in ENUM_CHAR_ALPHABET
                for key1 in Z26_INVERSES
            ]
        )

    @classmethod
    def _check_keys(cls, keys):
        try:
            key1, key2 = [int(key) for key in keys.strip().split(" ")]
            if key1 not in Z26_INVERSES:
                raise KeyError(
                    f"First Key is Invalid: {key1}"
                    + f"Valid Keys: {Z26_INVERSES}"
                )
            if key2 not in ENUM_CHAR_ALPHABET:
                raise KeyError(
                    f"Second Key is Invalid: {key2}"
                    + f"Valid Keys: {ENUM_CHAR_ALPHABET}"
                )
            return key1, key2
        except ValueError:
            raise ValueError(
                f"Not Parsable Keys: {keys}\n"
                + "Expected Format: FirstKey[SPACE]SecondKey"
            )
