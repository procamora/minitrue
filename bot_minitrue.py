#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://geekytheory.com/telegram-programando-un-bot-en-python/
# https://bitbucket.org/master_groosha/telegram-proxy-bot/src/07a6b57372603acae7bdb78f771be132d063b899/proxy_bot.py?at=master&fileviewer=file-view-default
# https://github.com/eternnoir/pyTelegramBotAPI/blob/master/telebot/types.py

"""commands
Name:
Automatic Scan Network

Username:
procamora_scan_bot

Description:
This is a bot to manage network scanner using nmap. A local agent is required to perform the scans

About:
This bot has been developed by @procamora

Botpic:
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
import ipaddress
import logging
import re
import subprocess
import sys
import threading
import time
import os
from pathlib import Path
from threading import Lock
from typing import NoReturn, Tuple, List, Text, Dict, IO, Callable

from procamora_utils.ip import IP
from procamora_utils.logger import get_logging
from requests import exceptions
# Importamos la librería Y los tipos especiales de esta
from telebot import TeleBot, types, apihelper
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from terminaltables import AsciiTable

from generate_pdf import latex_to_pdf, generate_latex
from host import Host
from implement_sqlite import select_hosts_online, select_hosts_offline, update_descriptions, check_database
from openvas import OpenVas, FULL_FAST
from scan_nmap import ScanNmap

log: logging = get_logging(False, 'bot_scan')


def get_basic_file_config():
    return f'''[BASICS]
ADMIN = {os.environ.get('TG_ADMIN')}
BOT_TOKEN = {os.environ.get('TG_BOT_TOKEN')}
DEBUG = 0
DELAY = 30

[DEBUG]
ADMIN = {os.environ.get('TG_ADMIN')}
BOT_TOKEN = {os.environ.get('TG_BOT_DEBUG_TOKEN')}

[OPENVAS]
IP = 192.168.1.71
USER = admin
PASSWD = admin
'''


my_commands: Tuple[Text, ...] = (
    '/scan',  # 0
    '/online',  # 1
    '/offline',  # 2
    '/pdf',  # 3
    '/help'  # -2
    '/exit',  # -1
)

FILE_CONFIG: Path = Path(Path(__file__).resolve().parent, "settings.cfg")
if not FILE_CONFIG.exists():
    log.warning(f'File {FILE_CONFIG} not exists and is necesary')
    FILE_CONFIG.write_text(get_basic_file_config())
    log.warning(f'Creating file {FILE_CONFIG}. It is necessary to configure the file.')
    #sys.exit(1)

config: configparser.ConfigParser = configparser.ConfigParser()
config.read(FILE_CONFIG)

config_basic: configparser.SectionProxy = config["BASICS"]

if bool(int(config_basic.get('DEBUG'))):
    bot: TeleBot = TeleBot(config["DEBUG"].get('BOT_TOKEN'))
else:
    bot: TeleBot = TeleBot(config_basic.get('BOT_TOKEN'))

owner_bot: int = int(config_basic.get('ADMIN'))

lock: Lock = Lock()


def get_markup_cmd() -> types.ReplyKeyboardMarkup:
    markup: types.ReplyKeyboardMarkup = types.ReplyKeyboardMarkup(one_time_keyboard=True)
    markup.row(my_commands[0])
    markup.row(my_commands[1], my_commands[2], my_commands[3])
    # markup.row(my_commands[4])
    return markup


def get_markup_new_host(host: Host):
    markup = InlineKeyboardMarkup()
    inline_keyboard: Tuple[InlineKeyboardButton, ...] = (InlineKeyboardButton('nmap', callback_data=f'nmap_{host.ip}'),
                                                         InlineKeyboardButton('openvas', callback_data=f'openvas_{host.ip}'),
                                                         InlineKeyboardButton('description', callback_data=f'description_{host.mac}'))
    markup.row_width = len(inline_keyboard)
    markup.add(InlineKeyboardButton('nmap', callback_data=f'nmap_{host.ip}'),
               InlineKeyboardButton('openvas', callback_data=f'openvas_{host.ip}'),
               InlineKeyboardButton('description', callback_data=f'description_{host.mac}'))
    return markup


def daemon_tcp_scan(ip: Text, message: types.Message):
    sn: ScanNmap = ScanNmap()
    ports, lport = sn.tcp_ip_scan(ipaddress.ip_interface(ip))
    bot.reply_to(message, ports, reply_markup=get_markup_cmd())


def daemon_openvas_scan(target: Text, message: types.Message):
    # get open ports
    sn: ScanNmap = ScanNmap()
    ports, lport = sn.tcp_ip_scan(ipaddress.ip_interface(target))
    ports_str: Text = ",".join(map(str, lport))

    ov: configparser.SectionProxy = config["OPENVAS"]
    openvas: OpenVas = OpenVas(IP(ip=ov.get('IP')), ov.get('USER'), ov.get('PASSWD'))
    # scan open ports
    report_id: Text = openvas.analize_ip(IP(ip=target), FULL_FAST, f'T: {ports_str}')
    bot.reply_to(message, f'Scanning of openvas to IP {target} in process.\nPorts: {ports_str}',
                 reply_markup=get_markup_cmd())

    stop: bool = False
    while not stop:
        list_tasks: Dict[Text, Tuple[Text, int, float]] = openvas.list_tasks()
        if report_id in list_tasks.keys() and list_tasks[report_id][1] == 100:
            stop = True
        else:
            bot.send_message(message.chat.id,
                             f'Scanning of openvas to IP {target}. in process.\nThis scan is very slow...',
                             reply_markup=get_markup_cmd())
        time.sleep(240)

    file: Path = openvas.report(report_id, 'pdf', Path('/tmp/'))
    file_data: IO = file.open('rb')
    bot.send_document(message.chat.id, file_data, reply_markup=get_markup_cmd())


def send_message_safe(message: types.Message, text: Text) -> NoReturn:
    if len(text) > 4096:
        new_msg = f'{str(text)[0:4050]}\n.................\nTruncated message'
        bot.reply_to(message, new_msg, reply_markup=get_markup_cmd())
    else:
        bot.reply_to(message, text, reply_markup=get_markup_cmd())


def report_and_repeat(message: types.Message, mac: Text, func: Callable, info: Text):
    """
    Metodo auxiliar con el que volver a preguntar tras una respuesta no valida
    :param message:
    :param protocol:
    :param func:
    :param info:
    :return:
    """
    bot.reply_to(message, info, reply_markup=get_markup_cmd())
    bot.register_next_step_handler(message, func, mac=mac)


def is_response_command(message: types.Message):
    response: bool = False
    if message.text[0] == '/':
        response = True

    if message.text == my_commands[-1]:  # exit
        bot.reply_to(message, "Cancelled the change of description", reply_markup=get_markup_cmd())
    elif message.text == my_commands[-2]:  # help
        command_help(message)
    elif message.text == my_commands[0]:  # scan
        send_scan(message)
    elif message.text == my_commands[1]:  # online
        send_online(message)
    elif message.text == my_commands[2]:  # offline
        send_offline(message)
    elif message.text == my_commands[3]:  # pdf
        send_pdf(message)
    return response


def check_description(message: types.Message, mac: Text) -> NoReturn:
    if is_response_command(message):
        return

    if not re.search(r'^(\w+| )+$', message.text):
        report_and_repeat(message, mac, check_description,
                          'Enter a valid description, it can only contains alphanumeric characters and space')
        return

    update_descriptions(mac, description=message.text, lock=lock)
    bot.reply_to(message, 'update description', reply_markup=get_markup_cmd())


@bot.callback_query_handler(func=lambda call: True)
def callback_query(call: types.CallbackQuery):
    ip: Text = call.data.split('_')[1]
    if re.search(r'nmap_.*', call.data):
        bot.answer_callback_query(call.id, f"run thread scan tcp nmap to {ip}")
        d = threading.Thread(target=daemon_tcp_scan, daemon=True, name='tcp_scan', args=(ip, call.message))
        d.start()
    elif re.search(r'openvas_.*', call.data):
        bot.answer_callback_query(call.id, f"run thread scan tcp openvas to {ip}")
        d = threading.Thread(target=daemon_openvas_scan, daemon=True, name='openvas_scan', args=(ip, call.message))
        d.start()
    elif re.search(r'description_.*', call.data):
        mac: Text = ip
        bot.answer_callback_query(call.id, f"creating description for {mac}")
        bot.reply_to(call.message, f'What description do you want to give to the host: {mac}', reply_markup=get_markup_cmd())
        bot.register_next_step_handler(call.message, check_description, mac=mac)


# Handle always first "/start" message when new chat with your bot is created
@bot.message_handler(commands=["start"])
def command_start(message: types.Message) -> NoReturn:
    bot.send_message(message.chat.id, f"Welcome to the bot\nYour id is: {message.chat.id}",
                     reply_markup=get_markup_cmd())
    command_system(message)
    return  # solo esta puesto para que no falle la inspeccion de codigo


@bot.message_handler(commands=["help"])
def command_help(message: types.Message) -> NoReturn:
    bot.send_message(message.chat.id, "Here I will put all the options")
    markup = types.InlineKeyboardMarkup()
    itembtna = types.InlineKeyboardButton('Github', url="https://github.com/procamora/bot_scan_networks")
    markup.row(itembtna)
    bot.send_message(message.chat.id, "Here I will put all the options", reply_markup=markup)
    return  # solo esta puesto para que no falle la inspeccion de codigo


@bot.message_handler(commands=["system"])
def command_system(message: types.Message) -> NoReturn:
    bot.send_message(message.chat.id, "List of available commands\nChoose an option: ", reply_markup=get_markup_cmd())
    return  # solo esta puesto para que no falle la inspeccion de codigo


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['exit'])
def send_exit(message: types.Message) -> NoReturn:
    bot.send_message(message, "Nothing", reply_markup=get_markup_cmd())
    return


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['scan'])
def send_scan(message: types.Message) -> NoReturn:
    bot.reply_to(message, 'Starting the network scan')
    # TODO THREAD AND subnet dynamic
    list_networks: List[ipaddress.ip_interface] = list()
    list_networks.append(ipaddress.ip_interface('192.168.1.0/24'))
    sn: ScanNmap = ScanNmap(list_networks)
    new_hosts: List[Host] = sn.run()
    if len(new_hosts) > 0:
        bot.reply_to(message, str(new_hosts), reply_markup=get_markup_cmd())
    else:
        bot.reply_to(message, 'No new host has been detected', reply_markup=get_markup_cmd())
    return


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['online'])
def send_online(message: types.Message) -> NoReturn:
    response: List[Host] = select_hosts_online(lock)
    update = list([['IP', 'Desc', 'Vendor']])
    for i in response:
        update.append((i.ip, i.description, i.vendor))

    table: AsciiTable = AsciiTable(update)
    send_message_safe(message, str(table.table))
    return


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['offline'])
def send_offline(message: types.Message) -> NoReturn:
    response: List[Host] = select_hosts_offline(lock)
    update = list([['IP', 'Desc', 'Vendor']])
    for i in response:
        update.append((i.ip, i.description, i.vendor))

    table: AsciiTable = AsciiTable(update)
    send_message_safe(message, str(table.table))
    return


@bot.message_handler(func=lambda message: message.chat.id == owner_bot, commands=['pdf'])
def send_pdf(message: types.Message) -> NoReturn:
    def daemon_generate_pdf(msg: types.Message):
        hosts_online: List[Host] = select_hosts_online(lock)
        hosts_offline: List[Host] = select_hosts_offline(lock)

        cmd_interfaces: Text = 'ip address show'
        stdout_interfaces, stderr, ex = execute_command(cmd_interfaces)
        cmd_arp: Text = 'ip neigh show | grep "lladdr"'
        stdout_arp, stderr, ex = execute_command(cmd_arp)
        cmd_routes: Text = 'ip route list'
        stdout_routes, stderr, ex = execute_command(cmd_routes)

        # logger.critical('chage generate latex, type all_host change')
        # sys.exit(60)
        string_latex = generate_latex(hosts_online, hosts_offline, stdout_interfaces, stdout_arp, stdout_routes)
        execute, file = latex_to_pdf(string_latex)

        if execute.returncode == 0:
            # IMPORTANTE para que el documento tenga nombre en tg tiene que enviarse un _io.BufferedReader con open()
            bot.send_document(msg.chat.id, file, reply_markup=get_markup_cmd(), )
        else:  # Si la salida del comando excede el limite de mensaje de Telegram se trunca
            send_message_safe(message, execute.stdout.decode('utf-8'))
        return

    d = threading.Thread(target=daemon_generate_pdf, daemon=True, name='generate_pdf', args=(message,))
    d.start()
    return


@bot.message_handler(func=lambda message: message.chat.id == owner_bot)
def text_not_valid(message: types.Message) -> NoReturn:
    texto: Text = 'unknown command, enter a valid command :)'
    bot.reply_to(message, texto, reply_markup=get_markup_cmd())
    return


@bot.message_handler(regexp=".*")
def handle_resto(message: types.Message) -> NoReturn:
    text: Text = "You're not allowed to perform this action, that's because you're not me.\n" \
                 'As far as you know, it disappears -.-'
    bot.reply_to(message, text, reply_markup=get_markup_cmd())
    return  # solo esta puesto para que no falle la inspeccion de codigo


def format_text(param_text: bytes) -> Text:
    """
    Metodo para formatear codigo, es usado para formatear las salidas de las llamadas al sistema
    :param param_text:
    :return:
    """
    if param_text is not None:
        text = param_text.decode('utf-8')
        return str(text)
    return str()  # Si es None retorno string vacio


def execute_command(command: Text) -> Tuple[Text, Text, subprocess.Popen]:
    """
    Metodo que realiza una llamada al sistema para ejecutar un comando
    :param command:
    :return:
    """
    # FIXME CAMBIAR Popen por run
    execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = execute.communicate()
    return format_text(stdout), format_text(stderr), execute


def daemon_aux(host: Host):
    """
    Funcion auxiliar usada por map para convertir la clase Host a un string y enviarlo por telegram cuando se detecta
    un nuevo host
    :param host:
    :return:
    """
    return f'Host(ip="{host.ip}", mac="{host.mac}", vendor="{host.vendor}", description="{host.description}")'


def daemon_scan_network() -> NoReturn:
    """
    Demonio que va comprobando si tiene que ejecutarse un recordatorio
    :return:
    """
    check_database()
    list_networks: List[ipaddress.ip_interface] = list()
    list_networks.append(ipaddress.ip_interface('192.168.1.0/24'))
    log.info(list_networks)
    sn: ScanNmap = ScanNmap(list_networks, lock)
    delay: int = int(config_basic.get('DELAY'))

    iteration: int = 0
    while True:
        # Al capturar el error en el nbucle infinito, si falla una vez por x motivo no afectaria,
        # ya que seguiria ejecutandose en siguientes iteraciones
        try:
            sn.update_db()  # Actualizamos dict de host, por si se han detectado nuevos
            if iteration % 5 == 0:  # scan avanzado que ejecutamos 1 de cada 5 escaneos
                log.info('scan TCP FIN')
                new_hosts: List[Host] = sn.run(sn.nmap_tcp_fin_scan, True)
            else:
                new_hosts: List[Host] = sn.run(sn.nmap_ping_scan, True)
            if len(new_hosts) > 0:
                for host in new_hosts:
                    bot.send_message(owner_bot, f'new host:  \n\n{host}', reply_markup=get_markup_new_host(host))

        except Exception as e:
            log.error(f'Fail thread: {e}')

        iteration += 1

        # https://stackoverflow.com/questions/17075788/python-is-time-sleepn-cpu-intensive
        time.sleep(delay)


def main():
    d = threading.Thread(target=daemon_scan_network, daemon=True, name='scan_network')
    d.start()

    try:
        bot.send_message(owner_bot, "Starting bot", reply_markup=get_markup_cmd(), disable_notification=True)
        log.info('Starting bot')
    except (apihelper.ApiException, exceptions.ReadTimeout) as e:
        log.critical(f'Error in init bot: {e}')
        sys.exit(1)

    # Con esto, le decimos al bot que siga funcionando incluso si encuentra algun fallo.
    bot.infinity_polling(none_stop=True)


if __name__ == "__main__":
    main()
