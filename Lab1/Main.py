from sys import argv
from os import getcwd
from AffineZ26 import *
from CaesarZ26 import *
from Cipher import *


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
    with open(getcwd()+'\\'+filename) as ifile:
        return ifile.read()


def write_file(text, filename):
    with open(getcwd()+'\\'+filename, 'w') as ofile:
        ofile.write(text)


if __name__ == '__main__':
    main(argv[1:])