from sys import argv
from sys import version_info as vrs
from os import getcwd

if vrs < (3, 8):
    raise SystemError(f'You need at least Python 3.8.0 to run this script. '
                      f'Your current version {vrs.major}.{vrs.minor}.{vrs.micro}')

from src.Cipher import Cipher
from src.CaesarZ26 import CaesarZ26
from src.AffineZ26 import AffineZ26


CIPHERS = {
    '-c' : CaesarZ26,
    '-a' : AffineZ26,
}

FLAGS = { '-e', '-d', '-j', '-k' }

FILEPATHS = {
    'plain' : '\\text_files\\plain.txt',
    'decrypt': '\\text_files\\decrypt.txt',
    'crypto': '\\text_files\\crypto.txt',
    'key': '\\text_files\\key.txt',
    'new-key': '\\text_files\\new-key.txt',
    'extra': '\\text_files\\extra.txt'
}

def main(argv):

    if len(argv) != 2:
        raise ValueError('You need to pass exactly two arguments.')
    else:
        cipher, flag = argv
        
        if cipher in CIPHERS.keys() and flag in FLAGS:
            cipher = CIPHERS[cipher]
        else:
            raise ValueError(f'Combination of this cipher {cipher} and this flag {flag} is not supported.')

        if flag == '-e':
            text = read_file(FILEPATHS['plain'])
            keys = get_keys(read_file(FILEPATHS['key']))
            encrypted = cipher.encrypt(text, keys)
            write_file(encrypted, FILEPATHS['crypto'])

        elif flag == '-d':
            text = read_file(FILEPATHS['crypto'])
            keys = get_keys(read_file(FILEPATHS['key']))
            decrypted = cipher.decrypt(text, keys)
            write_file(decrypted, FILEPATHS['decrypt'])

        elif flag == '-j':
            encrypted = read_file(FILEPATHS['crypto'])
            extra = read_file(FILEPATHS['extra'])
            key, decrypted = cipher.cryptoanalysis(encrypted, extra)
            write_file(decrypted, FILEPATHS['decrypt'])
            write_file(str(key), FILEPATHS['new-key'])

        elif flag == '-k':
            encrypted = read_file(FILEPATHS['crypto'])
            decryptions = cipher.bruteforce(encrypted)
            write_file(decryptions, FILEPATHS['decrypt'])


def read_file(filename):
    with open(getcwd()+filename, 'r') as ifile:
        text = ifile.read()
        if text == '':
            raise ValueError(f'File {filename} is empty')
        else:
            return text 


def write_file(text, filename):
    with open(getcwd()+filename, 'w') as ofile:
        open(getcwd()+filename, 'w').close() # clear output file
        ofile.write(text)


def get_keys(text):
    try:
        keys = [int(key) for key in text.split(' ')]
        return tuple(keys)
    except ValueError:
        raise ValueError('Provided keys are invalid')


if __name__ == '__main__':
    main(argv[1:])
