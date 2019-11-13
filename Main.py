from click import pass_context, option, group
from src.ciphers.CaesarZ26 import CaesarZ26
from src.ciphers.AffineZ26 import AffineZ26
from src.ciphers.VigenereZ26 import VigenereZ26
from src.utils.utils import read_file, write_file

# Functionality Support, used in --help
ENCRYPTION = ['Caesars', 'Affine', 'Vigenere']
DECRYPTION = ['Caesars', 'Affine', 'Vigenere']
CRYPTOANALYSIS = ['Caesars', 'Affine', 'Vigenere']
BRUTEFORCE = ['Caesars', 'Affine']

# Filepaths
ORIGINALTEXT = ['src', 'text_files', 'orig.txt']
PLAINTEXT = ['src', 'text_files', 'plain.txt']
EXTRATEXT = ['src', 'text_files', 'extra.txt']
KEY = ['src', 'text_files', 'key.txt']
NEWKEY = ['src', 'text_files', 'new-key.txt']
ENCRYPTED = ['src', 'text_files', 'crypto.txt']
DECRYPTED = ['src', 'text_files', 'decrypt.txt']


@group(chain=True)
@option('-c', 'cipher', flag_value=CaesarZ26, help='Ceasars Cipher')
@option('-a', 'cipher', flag_value=AffineZ26, help='Affine Cipher')
@option('-v', 'cipher', flag_value=VigenereZ26, help='Vigenere Cipher')
@pass_context
def main(ctx, cipher):
    '''
    \b
    Cryptography Script
    \b
    Expects two arguments,
    first one for the cipher you wish to use
    and the second one for desired functionality.
    \b
    Example Use Case:
    You want to encrypt text using Vigenere Cipher.

    >>> python main.py -v e

    Notice how the '-' sign is missing on the second arg.
    '''
    ctx.ensure_object(dict)
    ctx.obj['CIPHER'] = cipher


@main.command(
    'e',
    help=f'Encrypting, Supported: {ENCRYPTION}'
)
@pass_context
def encrypt(ctx):
    text = read_file(PLAINTEXT)
    key = read_file(KEY)
    encrypted = ctx.obj['CIPHER'].encrypt(text, key)
    write_file(encrypted, ENCRYPTED)


@main.command(
    'd',
    help=f'Decrypting, Supported: {DECRYPTION}'
)
@pass_context
def decrypt(ctx):
    text = read_file(ENCRYPTED)
    key = read_file(KEY)
    encrypted = ctx.obj['CIPHER'].encrypt(text, key)
    write_file(encrypted, DECRYPTED)


@main.command(
    'k',
    help=f'Cryptoanalysis, Supported: {CRYPTOANALYSIS}'
)
@pass_context
def cryptoanalysis(ctx):
    text = read_file(ENCRYPTED)
    if isinstance(ctx.obj['CIPHER'], (AffineZ26, CaesarZ26)):
        sample = read_file(EXTRATEXT)
        decrypted, key = ctx.obj['CIPHER'].cryptoanalysis(text, sample)
    else:
        key = ctx.obj['CIPHER'].cryptoanalysis(text)
        decrypted = ctx.obj['CIPHER'].decrypt(text, key)
    write_file(decrypted, DECRYPTED)
    write_file(key, NEWKEY)


@main.command(
    'j',
    help=f'Bruteforce Deciphering, Supported: {BRUTEFORCE}'
)
@pass_context
def bruteforce(ctx):
    encrypted = read_file(ENCRYPTED)
    decryptions = ctx.obj['CIPHER'].bruteforce(encrypted)
    write_file(decryptions, DECRYPTED)


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
