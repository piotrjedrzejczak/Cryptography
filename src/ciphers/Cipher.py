from abc import ABC, abstractmethod


class Cipher(ABC):
    @abstractmethod
    def encrypt(self):
        pass

    @abstractmethod
    def decrypt(self):
        pass

    @abstractmethod
    def cryptanalysis(self):
        pass

    @abstractmethod
    def crack(self):
        pass
