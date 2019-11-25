from ciphers.Caesar import Caesar
from ciphers.Affine import Affine
from ciphers.Vigenere import Vigenere
from ciphers.BitwiseXOR import BitwiseXOR
from utils.utils import read_file


PLAINTEXT = ['src', 'test', 'text_files', 'plain.txt']

CAESARS_KEY = ['src', 'test', 'text_files', 'caesar', 'key.txt']
CAESARS_ENCRYPTED = ['src', 'test', 'text_files', 'caesar', 'crypto.txt']

AFFINE_KEYS = ['src', 'test', 'text_files', 'affine', 'key.txt']
AFFINE_ENCRYPTED = ['src', 'test', 'text_files', 'affine', 'crypto.txt']

VIGENERE_KEY = ['src', 'test', 'text_files', 'vigenere', 'key.txt']
VIGENERE_ENCRYPTED = ['src', 'test', 'text_files', 'vigenere', 'crypto.txt']

XOR_KEY = ['src', 'test', 'text_files', 'xor', 'key.txt']
XOR_ENCRYPTED = ['src', 'test', 'text_files', 'xor', 'crypto.txt']


def test_ceasars_encryption():
    testf = read_file(CAESARS_ENCRYPTED)
    plainf = read_file(PLAINTEXT)
    keyf = read_file(CAESARS_KEY)
    encrypted = Caesar.encrypt(plainf, keyf)
    assert encrypted == testf


def test_ceasars_decryption():
    testf = read_file(PLAINTEXT)
    crypto = read_file(CAESARS_ENCRYPTED)
    keyf = read_file(CAESARS_KEY)
    decrypted = Caesar.decrypt(crypto, keyf)
    assert decrypted == testf


def test_affine_encryption():
    testf = read_file(AFFINE_ENCRYPTED)
    plainf = read_file(PLAINTEXT)
    keyf = read_file(AFFINE_KEYS)
    encrypted = Affine.encrypt(plainf, keyf)
    assert encrypted == testf


def test_affine_decryption():
    testf = read_file(PLAINTEXT)
    crypto = read_file(AFFINE_ENCRYPTED)
    keyf = read_file(AFFINE_KEYS)
    decrypted = Affine.decrypt(crypto, keyf)
    assert decrypted == testf


def test_vigenere_encryption():
    testf = read_file(VIGENERE_ENCRYPTED)
    plainf = read_file(PLAINTEXT)
    keyf = read_file(VIGENERE_KEY)
    encrypted = Vigenere.encrypt(plainf, keyf)
    assert encrypted == testf


def test_vigenere_decryption():
    testf = read_file(PLAINTEXT)
    crypto = read_file(VIGENERE_ENCRYPTED)
    keyf = read_file(VIGENERE_KEY)
    decrypted = Vigenere.decrypt(crypto, keyf)
    assert decrypted == testf


def test_vigenere_cryptoanalysis():
    testf = read_file(VIGENERE_KEY)
    crypto = read_file(VIGENERE_ENCRYPTED)
    keyword = Vigenere.cryptanalysis(crypto)
    assert keyword == testf


def test_bitwisexor_encryption():
    text = read_file(PLAINTEXT)
    testf = read_file(XOR_ENCRYPTED)
    keyf = read_file(XOR_KEY)
    encrypted = BitwiseXOR.encrypt(text, keyf)
    assert encrypted == testf


def test_bitwisexor_decryption():
    text = read_file(XOR_ENCRYPTED)
    testf = read_file(PLAINTEXT)
    keyf = read_file(XOR_KEY)
    decrypted = BitwiseXOR.decrypt(text, keyf)
    assert decrypted == testf


def test_bitwisexor_cryptanalysis():
    text = read_file(XOR_ENCRYPTED)
    testf = read_file(XOR_KEY)
    kw = BitwiseXOR.cryptanalysis(text)
    assert kw == testf
