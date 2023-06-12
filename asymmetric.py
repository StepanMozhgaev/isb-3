import logging

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


class Asymmetric:
    """
    Класс для генерации ассиметричных ключей
    """

    def __init__(self, public: str = None, private: str = None, decrypted: str = None, encrypted: str = None) -> None:
        """
        записываем пути файлов в поля класса
        :param public: путь к открытому ключу
        :param private: путь к закрытому ключу
        :param decrypted: путь к дешифрованному файлу
        :param encrypted: путь к зашифрованному файлу
        """
        self.public_pem = public
        self.private_pem = private
        self.encrypted = encrypted
        self.decrypted = decrypted

    def key_generation(self) -> None:
        """
        генерация ключей
        :param self: поля класса
        :return: None
        """
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024
        )
        private = keys
        public = keys.public_key()
        self.add_private(private)
        self.add_public(public)

    def add_public(self, public: str) -> None:
        """
        сереализация открытого ключа в файл
        :param public: открытый ключ
        :return: поля класса
        """
        try:
            with open(self.public_pem, "wb") as _public:
                _public.write(public.public_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo))
        except:
            logging.error(
                f"Ошибка открытия файла: {self.public_pem}"
            )

    def add_private(self, private: str) -> None:
        """
        сереализация закрытого ключа в файл
        :param private: закрытый ключ
        :return: None
        """
        try:
            with open(self.private_pem, "wb") as _private:
                _private.write(private.private_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                     encryption_algorithm=serialization.NoEncryption()))
        except:
            logging.error(
                f"Ошибка открытия файла: {self.private_pem}"
            )

    def add_encrypted(self, text: bytes) -> None:
        """
        десериализация текста в файл
        :param text: текст в байтах
        :return: None
        """
        try:
            with open(self.encrypted, "wb") as f:
                f.write(text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.encrypted}"
            )

    def add_decrypted(self, text: str) -> None:
        """
        десериализация текста в файл
        :param text: текст
        :return: None
        """
        try:
            with open(self.decrypted, "wb") as f:
                f.write(text)
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypted}"
            )

    def get_public(self) -> str:
        """
        десериализация открытого ключа
        :return: ключ(str)
        """
        try:
            with open(self.public_pem, "rb") as pub:
                public_bytes = pub.read()
            pub_key = load_pem_public_key(public_bytes)
            return pub_key
        except:
            logging.error(
                f"Ошибка открытия файла: {self.public_pem}"
            )

    def get_private(self) -> str:
        """
        десериализация закрытого ключа
        :return: ключ(str)
        """
        try:
            with open(self.private_pem, "rb") as priv:
                privae_bytes = priv.read()
            priv_key = load_pem_private_key(privae_bytes, password=None)
            return priv_key
        except:
            logging.error(
                f"Ошибка открытия файла: {self.private_pem}"
            )

    def get_encrypted(self) -> bytes:
        """
        десериализация зашифрованного текста
        :return: зашифрованный текст
        """
        try:
            with open(self.encrypted, "rb") as f:
                text = f.read()
                return text
        except:
            logging.error(
                f"Ошибка открытия файла: {self.encrypted}"
            )

    def encryption(self) -> None:
        """
        шифрование текста RSA_OAEP
        :return: None
        """

        _str = str()
        try:
            with open(self.decrypted, "rb") as f:
                _str = f.read()
        except:
            logging.error(
                f"Ошибка открытия файла: {self.decrypted}"
            )
        if type(_str) != bytes:
            text = bytes(_str, "UTF-8")
        else:
            text = _str
        public = self.get_public()
        _text = public.encrypt(text, padding.OAEP(mgf=padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self.add_encrypted(_text)

    def decryption(self) -> None:
        """
        дешифрование текста
        :return: None
        """
        priv_key = self.get_private()
        text = self.get_encrypted()
        _text = priv_key.decrypt(text,
                                 padding.OAEP(mgf=padding.MGF1(
                                     algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                                 )
        self.add_decrypted(_text)
