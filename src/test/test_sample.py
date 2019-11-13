from ciphers.Caesar import Caesar
from ciphers.Affine import Affine
from ciphers.Vigenere import Vigenere
from utils.utils import read_file


EMPTYFILE = ''
LARGE_PLAINTEXT_PATH = ['src', 'test', 'plain.txt']

PLAINTEXT = 'if the implementation is easy to explain, it may be a good idea.'

CAESARS_ENCRYPTED = 'pm aol ptwsltluahapvu pz lhzf av lewshpu, pa thf il h nvvk pklh.'  # noqa: E501
CAESARS_KEY = '7'

AFFINE_ENCRYPTED = 'wh zrc wqflcqcvzizwav wu ciuy za ctfliwv, wz qiy nc i maax wxci.'  # noqa: E501
AFFINE_KEYS = '5 8'

VIGENERE_ENCRYPTED = 'sw rwx wsgljuexkyibct zs jisi km tqdrris, qt wrw qx o mfoi qdor.'  # noqa: E501
VIGENERE_KEY = 'kryptografia'


def test_ceasars_encryption():
    encrypt = Caesar.encrypt(PLAINTEXT, CAESARS_KEY)
    assert encrypt == CAESARS_ENCRYPTED


def test_ceasars_decryption():
    decrypt = Caesar.decrypt(CAESARS_ENCRYPTED, CAESARS_KEY)
    assert decrypt == PLAINTEXT


def test_affine_encryption():
    encrypt = Affine.encrypt(PLAINTEXT, AFFINE_KEYS)
    assert encrypt == AFFINE_ENCRYPTED


def test_affine_decryption():
    decrypt = Affine.decrypt(AFFINE_ENCRYPTED, AFFINE_KEYS)
    assert decrypt == PLAINTEXT


def test_vigenere_encryption():
    encrypt = Vigenere.encrypt(PLAINTEXT, VIGENERE_KEY)
    assert encrypt == VIGENERE_ENCRYPTED


def test_vigenere_decryption():
    decrypt = Vigenere.decrypt(VIGENERE_ENCRYPTED, VIGENERE_KEY)
    assert decrypt == PLAINTEXT


def test_vigenere_cryptoanalysis():
    text = read_file(LARGE_PLAINTEXT_PATH)
    encrypted = Vigenere.encrypt(text, VIGENERE_KEY)
    keyword = Vigenere.cryptanalysis(encrypted)
    assert keyword == VIGENERE_KEY
