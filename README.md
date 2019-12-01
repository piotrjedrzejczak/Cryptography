# Cryptography

###  > Python 3

#### Example Usecase

    > python main.py -v e  # Encrypt text with Vigenere's Cipher

#### Currently Supported Ciphers

    - Caesar's Cipher (-c)
    - Affine Cipher (-a)
    - Vigenere Cipher (-v)
    - Bitwise XOR (-b)
    - Electronic Code Book Mode [EBC] (-ebc)
    - Cipher Block Chanining Mode [CBC] (-cbc)

#### Functionalities

    - Encryption (e)
    - Decryption (d)
    - Cryptanalysis (k)
    - Bruteforce Decryption (j) [Only Caesar's and Affine]
    - Text Normalization (p) [-> Lowercase, stripped text with spaces]

#### IO Files

    - plain.txt         > Normalized plain text read for encryption.
    - decrypt.txt       > Decrypted text.
    - crypto.txt        > Encrypted text.
    - key.txt           > Input file for key/keys.
    - new-key.txt       > Output file for key/keys found during cryptanalysis.
    - orig.txt          > Raw text.
    - extra.txt         > Partially decrypted plain text - Used in cryptanalysis in some ciphers.
    - img/orig.txt      > Original BMP file.
    - img/crypto.bmp    > Encrypted BMP file.