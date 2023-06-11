import argparse
import json
import logging
import os

from enc_dec import key_gener, encrypt, decrypt


def check_size(size: int):
    """
    проверка размерности ключа
    :param size: длина ключа
    :return: size: провернныый размер
    true or false: идентификатор проверки
    """
    if size == 128 or size == 192 or size == 256:
        return int(size / 8), True
    return 16, False


def get_arg():
    """
    получаем аргументы
    :return: args(Namespase) - аргументы
    """
    pars = argparse.ArgumentParser()
    pars.add_argument("-gen", "--generation", action="store_true", help="Сгенерировать ключи")
    pars.add_argument("-enc", "--encryption", action="store_true",
                      help="Зашифровать данные")
    pars.add_argument("-dec", "--decryption", action="store_true",
                      help="Расшифровать данные")
    _args = pars.parse_args()
    return _args


def config_file(name: str) -> str:
    """
    читаем пути из json файла
    :param name: название конфиг файла
    :return: считанный файл
    """
    CONFIG = os.path.join(name)
    sett = str()
    try:
        with open(CONFIG) as js_f:
            sett = json.load(js_f)
    except FileNotFoundError:
        logging.error(
            f"Ошибка открытия файла: {CONFIG} \nЗавершение работы..."
        )
        exit()
    return sett


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    args = get_arg()
    mode = (args.generation, args.encryption, args.decryption)
    sett = config_file("paths.json")
    size = int(sett["size"])
    size, correct = check_size(size)
    if not correct:
        logging.info("Размер ключа некорректный, уставновлен стандартный(128)")
    else:
        logging.info(f"Размер ключa: {size * 8}")

    logging.info("Генерация ключей \n ---------->")
    key_gener(sett["private"], sett["public"], sett["symmetric_key"], sett["symmetric_key_dec"], size)
    logging.info("Ключи сгенерированны")

    logging.info("Шифрование: \n ------>")
    encrypt(sett["text_file"], sett["private"], sett["symmetric_key"], sett["encrypted"],
            sett["symmetric_key_dec"], size)
    logging.info("Данные зашифрованы")

    logging.info("Дешифрование: \n ------->")
    decrypt(sett["encrypted"], sett["private"], sett["symmetric_key"], sett["decrypted"],
            sett["symmetric_key_dec"], size)
    logging.info("Данные расшифрованы")
