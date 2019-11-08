from abc import ABC, abstractmethod


class Cipher(ABC):
    @abstractmethod
    def encrypt(self):
        pass

    @abstractmethod
    def decrypt(self):
        pass

    @abstractmethod
    def cryptoanalysis(self):
        pass

    @abstractmethod
    def bruteforce(self):
        pass
