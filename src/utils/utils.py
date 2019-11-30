from os import path, getcwd
from re import sub


def readf(filepath, binary=False):
    if binary:
        with open(path.join(getcwd(), *filepath), 'rb') as bf:
            text = bf.read()
    else:
        with open(path.join(getcwd(), *filepath), 'r', encoding='utf-8') as f:
            text = f.read()
    if text:
        return text
    else:
        raise ValueError(f"File {filepath[-1]} is empty.")


def writef(text, filepath, binary=False):
    if binary:
        f = open(path.join(getcwd(), *filepath), 'wb')
    else:
        f = open(path.join(getcwd(), *filepath), 'w')
    # Clearing file
    open(path.join(getcwd(), *filepath), 'w').close()
    f.write(text)


def normalize_text(text):
    '''Returns lowercase, stripped text with spaces.'''
    return sub(r'[^a-zA-Z ]+', '', text).strip().lower()


def xor(vec1, vec2):
    ''' XOR's two vectors, if they're of different length,
        shorter one will be padded with zeros.
        Returns bytearray.
    '''
    if len(vec1) != len(vec2):
        diff = abs(len(vec1)-len(vec2))
        if len(vec1) < len(vec2):
            vec1 += bytearray(diff)
        else:
            vec2 += bytearray(diff)
    return bytearray([vec1[i] ^ vec2[i] for i in range(len(vec1))])
