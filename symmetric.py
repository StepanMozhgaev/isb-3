import os
import logging

from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Symmetric:
    """
    Класс для генерации симметрчного ключа, использует AES-шифрование
    Размер ключа в битах: 128,192 или 256
    """

    def __init__(self, size: int, key: str, decrypted: str = None, encrypted: str = None) -> None:
        """
        запись путей в поля класса
        :param size: размер ключа
        :param key: путь к ключу
        :param decrypted:  путь к расшифрованному файлу
        :param encrypted: путь к зашифрованному файлу
        """
        self.size = size
        self.key = key
        self.decrypted = decrypted
        self.encrypted = encrypted

    def add_key(self, _key: bytes) -> None:
        """
        сериализация ключа в файл
        :param _key: ключ
        :return: None
        """
        try:
            with open(self.key, "wb") as f:
                f.write(_key)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.key}"
            )

    def add_encrypted(self, text: bytes) -> None:
        """
        Запись зашифрованного текста в файл
        :param text: текст
        :return: None
        """
        try:
            with open(self.encrypted, "wb") as f:
                f.write(text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.encrypted}"
            )

    def add_decrypted(self, text: bytes) -> None:
        """
        запись расшифрованного текста
        :param text: текст
        :return: None
        """
        try:
            with open(self.decrypted, "w") as f:
                f.write(text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypted}"
            )

    def get_key(self) -> bytes:
        """
        десериализация ключа смметричного алгоритма
        :return: ключ(bytes)
        """
        try:
            with open(self.key, "rb") as f:
                return f.read()
        except:
            logging.error(
                f"Ошибка открытия файла: {self.key}"
            )

    def generate(self) -> None:
        """
        генерация ключа
        :return: None
        """
        _key = os.urandom(self.size)
        self.add_key(_key)

    def padding_data(self, _str: str) -> bytes:
        """
        добавляем незначащие данные к информации
        :param _str: дополняемая строка
        :return: дополненные данные
        """
        padd = padding.ANSIX923(AES.block_size).padder()
        text = bytes(_str, "UTF-8")
        padd_text = padd.update(text) + padd.finalize()
        return padd_text

    def encryption(self) -> None:
        """
        шифрование текста
        :return: None
        """
        _str = str()
        try:
            with open(self.decrypted, "rb", encodinf="UTF-8") as f:
                _str = f.read()
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypted}"
            )
        i = os.urandom(16)
        key = self.get_key()
        cipher = Cipher(algorithms.AES(key), modes.CBC(i), backend=default_backend())
        _str = self.padding_data(_str)
        encryptor = cipher.encryptor()
        text = i + encryptor.update(_str) + encryptor.finalize()
        self.add_encrypted(text)

    def depadding(self, text: str) -> bytes:
        """
        убираем из данных добавленные символы
        :text: текст, из которого убираем символы
        :return: востановленный текст
        """
        last = text[-1]
        if isinstance(last, int):
            return last
        else:
            return ord(last)

    def decryption(self) -> None:
        """
        дешифрование текста
        :return: None
        """
        text = bytes()
        try:
            with open(self.encrypted, "rb") as f:
                text = f.read()
        except:
            logging.error(
                f"Ошибка открытия файла: {self.encrypted}"
            )
            exit()
        i = text[:16]
        text = text[16:]

        cipher = Cipher(algorithms.AES(self.get_key()), modes.CBC(i), backend=default_backend())
        decryptor = cipher.decryptor()
        _text = decryptor.update(text) + decryptor.finalize()

        padd = self.depadding(_text)
        _text = _text[:-padd]
        _text = _text.decode("UTF-8")
        self.add_decrypted(_text)
