#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://geekytheory.com/telegram-programando-un-bot-en-python/
# https://bitbucket.org/master_groosha/telegram-proxy-bot/src/07a6b57372603acae7bdb78f771be132d063b899/proxy_bot.py?at=master&fileviewer=file-view-default
# https://github.com/eternnoir/pyTelegramBotAPI/blob/master/telebot/types.py

"""commands
Name:
procamora_scan_bot

Description:
This is a bot to manage network scanner using nmap. A local agent is required to perform the scans

About: 🚫
This bot has been developed by @procamora

Botpic: 🖼
<imagen del bot>

Commands:
scan - scan networks
online - get hosts online
offline - get hosts offline
pdf - get pdf report
help - Show help
start - Start the bot
"""

import configparser
import sys
import threading
import time
from ipaddress import IPv4Interface, IPv6Interface
from pathlib import Path
from typing import NoReturn, Tuple, List, Union, Text, Dict

from requests import exceptions
# Importamos la librería Y los tipos especiales de esta
from telebot import TeleBot, types, apihelper

from generate_pdf import latex_to_pdf, generate_latex
from host import Host
from implement_sqlite import select_all_hosts
from scan_nmap import ScanNmap, logger


def get_basic_file_config():
    return '''[BASICS]
ADMIN = 111111
BOT_TOKEN = 1069111113:AAHOk9K5TAAAAAAAAAAIY1OgA_LNpAAAAA
'''


my_commands: Tuple = (
    '/scan',  # 0
    '/online',  # 1
    '/offline',  # 2
    '/pdf',  # 3
    '/exit',  # 4
)

FILE_CONFIG: Path = Path('settings.ini')
if not FILE_CONFIG.exists():
    logger.critical(f'File {FILE_CONFIG} not exists and is necesary')
    FILE_CONFIG.write_text(get_basic_file_config())
    logger.critical(f'Creating file {FILE_CONFIG}. It is necessary to configure the file.')
    sys.exit(1)

config: configparser.ConfigParser = configparser.ConfigParser()
config.read(FILE_CONFIG)

config_basic: configparser.SectionProxy = config["BASICS"]

bot: TeleBot = TeleBot(config_basic.get('BOT_TOKEN'))


def get_keyboard() -> types.ReplyKeyboardMarkup:
    markup: types.ReplyKeyboardMarkup = types.ReplyKeyboardMarkup(one_time_keyboard=True)
    markup.row(my_commands[0])
    markup.row(my_commands[1], my_commands[2], my_commands[3])
    # markup.row(my_commands[4])
    return markup


# Handle always first "/start" message when new chat with your bot is created
@bot.message_handler(commands=["start"])
def command_start(message) -> NoReturn:
    bot.send_message(message.chat.id, f"Bienvenido al bot\nTu id es: {message.chat.id}")
    command_system(message)
    return  # solo esta puesto para que no falle la inspeccion de codigo


@bot.message_handler(commands=["help"])
def command_help(message) -> NoReturn:
    bot.send_message(message.chat.id, "Aqui pondre todas las opciones")
    markup = types.InlineKeyboardMarkup()
    itembtna = types.InlineKeyboardButton('Github', url="https://github.com/procamora/bot_scan_networks")
    markup.row(itembtna)
    bot.send_message(message.chat.id, "Aqui pondre todas las opciones", reply_markup=markup)
    return  # solo esta puesto para que no falle la inspeccion de codigo


@bot.message_handler(commands=["system"])
def command_system(message) -> NoReturn:
    bot.send_message(message.chat.id, "Lista de comandos disponibles")

    bot.send_message(message.chat.id, "Escoge una opcion: ", reply_markup=get_keyboard())
    return  # solo esta puesto para que no falle la inspeccion de codigo


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['exit'])
def send_exit(message) -> NoReturn:
    pass


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['scan'])
def send_scan(message) -> NoReturn:
    return


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['online'])
def send_online(message) -> NoReturn:
    return


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['offline'])
def send_offline(message) -> NoReturn:
    return


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['pdf'])
def send_pdf(message) -> NoReturn:
    all_hosts: Dict[Text, Host] = select_all_hosts()

    a = generate_latex(all_hosts)
    c, d = latex_to_pdf(a)

    # IMPORTANTE para que el dicumento tenga nombre en tg tiene que enviarse un _io.BufferedReader con open()
    bot.send_document(message.chat.id, d, reply_markup=get_keyboard(), )
    return


@bot.message_handler(regexp=".*")
def handle_resto(message) -> NoReturn:
    texto: Text = 'No tienes permiso para ejecutar esta accion, eso se debe a que no eres yo.\n' \
                  'Por lo que ya sabes, desaparece -.-'
    bot.reply_to(message, texto, reply_markup=get_keyboard())
    return  # solo esta puesto para que no falle la inspeccion de codigo


def daemon_scan_network() -> NoReturn:
    """
    Demonio que va comprobando si tiene que ejecutarse un recordatorio
    :return:
    """
    list_networks: List[Union[IPv4Interface, IPv6Interface]] = list()
    list_networks.append(IPv4Interface('192.168.1.0/24'))
    sn: ScanNmap = ScanNmap(list_networks)
    while True:
        new_hosts: List[Host] = sn.run()
        if len(new_hosts) > 0:
            bot.send_message(owner_bot, str(new_hosts))

        # https://stackoverflow.com/questions/17075788/python-is-time-sleepn-cpu-intensive
        time.sleep(300)


d = threading.Thread(target=daemon_scan_network, name='scan_network')
d.setDaemon(True)
d.start()

owner_bot: int = int(config_basic.get('ADMIN'))
try:
    bot.send_message(owner_bot, "Starting bot", reply_markup=get_keyboard(), disable_notification=True)
    logger.info('Starting bot')
except (apihelper.ApiException, exceptions.ReadTimeout) as e:
    logger.critical(f'Error in init bot: {e}')
    sys.exit(1)

# Con esto, le decimos al bot que siga funcionando incluso si encuentra algun fallo.
bot.infinity_polling(none_stop=True)
