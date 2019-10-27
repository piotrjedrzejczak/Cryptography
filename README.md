# Cryptography Class

###  > Python 3.8.0

#### Example Usecase

    > python main.py -c -e  # Encrypt text with Ceasar's Cipher

#### Currently Supported Ciphers

    - Lab I
        - Caesar's Cipher (-c)
        - Affine Cipher (-a)
    - Lab II
        - Vigenere Cipher (-v)

#### Functionalities

    - Encryption (-e)
    - Decryption (-d)
    - Cryptoanalysis based on partially decrypted text (-j)
    - Bruteforce decryption (-k)

#### Text Files

    - *plain.txt*    > Plain text you would like to encrypt.
    - *decrypt.txt*  > Decrypted text.
    - *crypto.txt*   > Encrypted text.
    - *key.txt*      > Input file for keys. In case of multiple keys delimit with [SPACE].
    - *new-key.txt*  > Output file for keys found during cryptoanalysis.
    - *extra.txt*    > Partially decrypted text used for cryptoanalysis.
