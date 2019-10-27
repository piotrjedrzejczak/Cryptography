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

def main(argv):

    if len(argv) != 2:
        raise ValueError('You need to pass exactly two arguments.')
    else:
        cipher, flag = argv
        
        if cipher in CIPHERS.keys() and flag in FLAGS:
            cipher = CIPHERS[cipher]
        else:
            return f'Combination of this cipher {cipher} and this flag {flag} is not supported.'

        if flag == '-e':
            text = read_file('plain.txt')
            keys = [ int(key) for key in read_file('key.txt').split(' ') ]
            if len(keys) == 1: keys = keys[0]
            encrypted = cipher.encrypt(text, keys)
            write_file(encrypted, 'crypto.txt')

        elif flag == '-d':
            text = read_file('crypto.txt')
            keys = [ int(key) for key in read_file('key.txt').split(' ') ]
            if len(keys) == 1: keys = keys[0]
            decrypted = cipher.decrypt(text, keys)
            write_file(decrypted, 'decrypt.txt')

        elif flag == '-j':
            encrypted = read_file('crypto.txt')
            plain = read_file('extra.txt')
            key, decrypted = cipher.cryptoanalysis(encrypted, plain)
            write_file(decrypted, 'decrypt.txt')
            write_file(str(key), 'new-key.txt')

        elif flag == '-k':
            encrypted = read_file('crypto.txt')
            decryptions = cipher.bruteforce(encrypted)
            write_file(decryptions, 'decrypt.txt')

        else:
            return f'Unidentified flag {argv[1]}'

def read_file(filename):
    with open(getcwd()+'\\text_files\\'+filename, 'r') as ifile:
        text = ifile.read()
        if text == '':
            raise ValueError(f'File {filename} is empty')
        else:
            return text 

def write_file(text, filename):
    with open(getcwd()+'\\text_files\\'+filename, 'w') as ofile:
        open(getcwd()+'\\text_files\\'+filename, 'w').close() # clear output file
        ofile.write(text)


if __name__ == '__main__':
    main(argv[1:])
    