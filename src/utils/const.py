from string import ascii_lowercase as al

# {a, b, c, ...}
ALPHABET_SET = set(al)

# {a: 0, b: 1, c: 2, ...}
CHAR_ENUM_ALPHABET = {char: enum for enum, char in enumerate(al)}

# {0: a, 1: b, 2: c, ...}
ENUM_CHAR_ALPHABET = {enum: char for enum, char in enumerate(al)}

# English Index of Coincidence
# https://en.wikipedia.org/wiki/Index_of_coincidence
ENGLISH_IOC = {
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

# All valid inverses in Z26
Z26_INVERSES = {
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
