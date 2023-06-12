from asymmetric import Asymmetric
from symmetric import Symmetric


def encrypt(_decrypted: str, private_key: str, symmetric_key: str, encrypted: str, symmetric_dec_key,
            size: int) -> None:
    """
    шифрование данных
    :param _decrypted: путь к расшифрованному тексту
    :param private_key: путь к закрытому ключу
    :param symmetric_key: путь к симметричносу ключу
    :param encrypted: путь к зашифрованному тексту
    :param symmetric_dec_key: путь к симметричному расшифрованному ключу
    :param size: размер ключа
    :return: None
    """
    assym = Asymmetric(private=private_key, decrypted=symmetric_dec_key, encrypted=symmetric_key)
    assym.decryption()
    sym = Symmetric(size, symmetric_dec_key, _decrypted, encrypted)
    sym.encryption()


def decrypt(encrypted: str, private_key: str, symmetric_key: str, _decrypted, symmetric_dec_key: str,
            size: int) -> None:
    """
    дешифровка
    :param encrypted: путь к зашифрованному тексту
    :param private_key: путь к закрытому ключу
    :param symmetric_key: путь к симметричному ключу
    :param _decrypted: путь к расшифрованному тексту
    :param symmetric_dec_key: путь к симметричному расшифрованному ключу
    :param size: размер ключа
    :return: None
    """
    assym = Asymmetric(private=private_key, decrypted=symmetric_dec_key, encrypted=symmetric_key)
    assym.decryption()
    sym = Symmetric(size, symmetric_dec_key, _decrypted, encrypted)
    sym.decryption()


def key_generation(private: str, public: str, symmetric_key: str, symmetric_dec_key: str, size: int) -> None:
    """
    генерация ключей
    :param private: путь к закрытому ключу
    :param public: путь к открытому ключу
    :param symmetric_key: путь к симметричному ключу
    :param symmetric_dec_key: путь к симметричному расшифрованному ключу
    :param size: размер ключа
    :return: None
    """
    assym = Asymmetric(public, private, symmetric_dec_key, symmetric_key)
    assym.key_generation()

    symm = Symmetric(size, symmetric_dec_key)
    symm.generate()

    assym.encryption()
