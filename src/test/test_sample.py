from ciphers.Caesar import Caesar
from ciphers.Affine import Affine
from ciphers.Vigenere import Vigenere
from ciphers.BitwiseXOR import BitwiseXOR
from utils.utils import readf


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
    testf = readf(CAESARS_ENCRYPTED)
    plainf = readf(PLAINTEXT)
    keyf = readf(CAESARS_KEY)
    encrypted = Caesar.encrypt(plainf, keyf)
    assert encrypted == testf


def test_ceasars_decryption():
    testf = readf(PLAINTEXT)
    crypto = readf(CAESARS_ENCRYPTED)
    keyf = readf(CAESARS_KEY)
    decrypted = Caesar.decrypt(crypto, keyf)
    assert decrypted == testf


def test_affine_encryption():
    testf = readf(AFFINE_ENCRYPTED)
    plainf = readf(PLAINTEXT)
    keyf = readf(AFFINE_KEYS)
    encrypted = Affine.encrypt(plainf, keyf)
    assert encrypted == testf


def test_affine_decryption():
    testf = readf(PLAINTEXT)
    crypto = readf(AFFINE_ENCRYPTED)
    keyf = readf(AFFINE_KEYS)
    decrypted = Affine.decrypt(crypto, keyf)
    assert decrypted == testf


def test_vigenere_encryption():
    testf = readf(VIGENERE_ENCRYPTED)
    plainf = readf(PLAINTEXT)
    keyf = readf(VIGENERE_KEY)
    encrypted = Vigenere.encrypt(plainf, keyf)
    assert encrypted == testf


def test_vigenere_decryption():
    testf = readf(PLAINTEXT)
    crypto = readf(VIGENERE_ENCRYPTED)
    keyf = readf(VIGENERE_KEY)
    decrypted = Vigenere.decrypt(crypto, keyf)
    assert decrypted == testf


def test_vigenere_cryptoanalysis():
    testf = readf(VIGENERE_KEY)
    crypto = readf(VIGENERE_ENCRYPTED)
    keyword = Vigenere.cryptanalysis(crypto)
    assert keyword == testf


def test_bitwisexor_encryption():
    text = readf(PLAINTEXT)
    testf = readf(XOR_ENCRYPTED)
    keyf = readf(XOR_KEY)
    encrypted = BitwiseXOR.encrypt(text, keyf)
    assert encrypted == testf


def test_bitwisexor_decryption():
    text = readf(XOR_ENCRYPTED)
    testf = readf(PLAINTEXT)
    keyf = readf(XOR_KEY)
    decrypted = BitwiseXOR.decrypt(text, keyf)
    assert decrypted == testf


def test_bitwisexor_cryptanalysis():
    text = readf(XOR_ENCRYPTED)
    testf = readf(XOR_KEY)
    kw = BitwiseXOR.cryptanalysis(text)
    assert kw == testf
