from click import pass_context, option, group
from ciphers.Caesar import Caesar
from ciphers.Affine import Affine
from ciphers.Vigenere import Vigenere
from ciphers.BitwiseXOR import BitwiseXOR
from ciphers.ECB import ECB
from ciphers.CBC import CBC
from utils.utils import readf, writef, normalize_text

# Functionality Support, used in --help
ENCRYPTION = ['Caesars', 'Affine', 'Vigenere', 'BitwiseXOR', 'ECB', 'CBC']
DECRYPTION = ['Caesars', 'Affine', 'Vigenere', 'BitwiseXOR']
CRYPTANALYSIS = ['Caesars', 'Affine', 'Vigenere', 'BitwiseXOR']
CRACK = ['Caesars', 'Affine']

# Filepaths
ORIGINALIMG = ['src', 'img', 'orig.bmp']
ENCRYPTEDIMG = ['src', 'img', 'crypto.bmp']
ORIGINALTEXT = ['src', 'text_files', 'orig.txt']
PLAINTEXT = ['src', 'text_files', 'plain.txt']
EXTRATEXT = ['src', 'text_files', 'extra.txt']
KEY = ['src', 'text_files', 'key.txt']
NEWKEY = ['src', 'text_files', 'new-key.txt']
ENCRYPTED = ['src', 'text_files', 'crypto.txt']
DECRYPTED = ['src', 'text_files', 'decrypt.txt']


@group(chain=True)
@option('-c', 'cipher', flag_value=Caesar, help='Ceasars Cipher')
@option('-a', 'cipher', flag_value=Affine, help='Affine Cipher')
@option('-v', 'cipher', flag_value=Vigenere, help='Vigenere Cipher')
@option('-b', 'cipher', flag_value=BitwiseXOR, help='Bitwise XOR')
@option('-ecb', 'cipher', flag_value=ECB, help='Electronic Codebook Demo')
@option('-cbc', 'cipher', flag_value=CBC, help='Cipher Block Chaining Demo')
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
    help=f'Encryption, Supported: {ENCRYPTION}'
)
@pass_context
def encrypt(ctx):

    if (ctx.obj['CIPHER'] == ECB or
            ctx.obj['CIPHER'] == CBC):
        img = readf(ORIGINALIMG, binary=True)
        encrypted = ctx.obj['CIPHER'].encrypt(img)
        writef(encrypted, ENCRYPTEDIMG, binary=True)
    else:
        key = readf(KEY)
        text = readf(PLAINTEXT)
        encrypted = ctx.obj['CIPHER'].encrypt(text, key)
        writef(encrypted, ENCRYPTED)


@main.command(
    'd',
    help=f'Decryption, Supported: {DECRYPTION}'
)
@pass_context
def decrypt(ctx):
    text = readf(ENCRYPTED)
    key = readf(KEY)
    decrypted = ctx.obj['CIPHER'].decrypt(text, key)
    writef(decrypted, DECRYPTED)


@main.command(
    'k',
    help=f'Cryptanalysis, Supported: {CRYPTANALYSIS}'
)
@pass_context
def cryptanalysis(ctx):
    text = readf(ENCRYPTED)
    if (ctx.obj['CIPHER'] == Affine or
            ctx.obj['CIPHER'] == Caesar):
        sample = readf(EXTRATEXT)
        decrypted, key = ctx.obj['CIPHER'].cryptanalysis(text, sample)
    else:
        key = ctx.obj['CIPHER'].cryptanalysis(text)
        decrypted = ctx.obj['CIPHER'].decrypt(text, key)
    writef(decrypted, DECRYPTED)
    writef(key, NEWKEY)


@main.command(
    'j',
    help=f'Cracking, Supported: {CRACK}'
)
@pass_context
def cracking(ctx):
    encrypted = readf(ENCRYPTED)
    decryptions = ctx.obj['CIPHER'].crack(encrypted)
    writef(decryptions, DECRYPTED)


@main.command(
    'p',
    help='Normalize Text'
)
@pass_context
def normalized(ctx):
    orig = readf(ORIGINALTEXT)
    normalized = normalize_text(orig)
    writef(normalized, PLAINTEXT)


if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
