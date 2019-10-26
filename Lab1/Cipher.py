import abc

class Cipher(abc.ABC):
    
    @abc.abstractmethod
    def encrypt(self):
        pass
    @abc.abstractmethod
    def decrypt(self):
        pass
    @abc.abstractmethod
    def cryptoanalysis(self):
        pass
    @abc.abstractmethod
    def bruteforce(self):
        pass