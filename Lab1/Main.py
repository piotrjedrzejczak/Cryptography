import sys
from AffineZ26 import *
from CaesarZ26 import *
from Cipher import *


CIPHERS = {
    '-c' : CaesarZ26,
    '-a' : AffineZ26,
}
FLAGS = {
    '-e' : Cipher.encrypt,
    '-d' : Cipher.decrypt,
    '-j' : Cipher.cryptoanalysis,
    '-k' : Cipher.bruteforce
}

def main(argv):

    if len(argv) != 2:
        raise ValueError('You need to pass exactly two arguments.')
    else:
        try:
            cipher = CIPHERS[argv[0]]
        except KeyError:
            return f'Unidentified cipher {argv[0]}'

        try:
            flag = FLAGS[argv[1]]
        except KeyError:
            return f'Unidentified flag {argv[1]}'

        cipher.flag


if __name__ == '__main__':
    main(sys.argv[1:])