from ciphers.CaesarZ26 import CaesarZ26
from ciphers.AffineZ26 import AffineZ26
from ciphers.VigenereZ26 import VigenereZ26
from utils.utils import read_file


EMPTYFILE = ''
LARGE_PLAINTEXT_PATH = ['src', 'test', 'plain.txt']

PLAINTEXT = 'if the implementation is easy to explain, it may be a good idea.'

CAESARS_ENCRYPTED = 'pm aol ptwsltluahapvu pz lhzf av lewshpu, pa thf il h nvvk pklh.'
CAESARS_KEY = '7'

AFFINE_ENCRYPTED = 'wh zrc wqflcqcvzizwav wu ciuy za ctfliwv, wz qiy nc i maax wxci.'
AFFINE_KEYS = '5 8'

VIGENERE_ENCRYPTED = 'sw rwx wsgljuexkyibct zs jisi km tqdrris, qt wrw qx o mfoi qdor.'
VIGENERE_KEY = 'kryptografia'


def test_ceasars_encryption():
    encrypt = CaesarZ26.encrypt(PLAINTEXT, CAESARS_KEY)
    assert encrypt == CAESARS_ENCRYPTED


def test_ceasars_decryption():
    decrypt = CaesarZ26.decrypt(CAESARS_ENCRYPTED, CAESARS_KEY)
    assert decrypt == PLAINTEXT


def test_affine_encryption():
    encrypt = AffineZ26.encrypt(PLAINTEXT, AFFINE_KEYS)
    assert encrypt == AFFINE_ENCRYPTED


def test_affine_decryption():
    decrypt = AffineZ26.decrypt(AFFINE_ENCRYPTED, AFFINE_KEYS)
    assert decrypt == PLAINTEXT


def test_vigenere_encryption():
    encrypt = VigenereZ26.encrypt(PLAINTEXT, VIGENERE_KEY)
    assert encrypt == VIGENERE_ENCRYPTED


def test_vigenere_decryption():
    decrypt = VigenereZ26.decrypt(VIGENERE_ENCRYPTED, VIGENERE_KEY)
    assert decrypt == PLAINTEXT


def test_vigenere_cryptoanalysis():
    text = read_file(LARGE_PLAINTEXT_PATH)
    encrypted = VigenereZ26.encrypt(text, VIGENERE_KEY)
    keyword = VigenereZ26.cryptoanalysis(encrypted)
    assert keyword == VIGENERE_KEY
