#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import logging
from pathlib import Path  # nueva forma de trabajar con rutas
from threading import Lock
from typing import List, Text, NoReturn, Tuple, Any, Dict

from procamora_utils.interface_sqlite import conection_sqlite, execute_script_sqlite
from procamora_utils.logger import get_logging

from host import Host

logger: logging = get_logging(False, 'sqlite')

# Ruta absoluta de la BD
DB: Path = Path(Path(__file__).resolve().parent, "database.db")
DB_STRUCTURE: Path = Path(Path(__file__).resolve().parent, "database.db.sql")


def get_list_host(response_query_str: List[Dict[Text, Any]]):
    response_query: List[Host] = list(
        map(lambda h: Host(h['ip'], h['mac'], h['vendor'], h['date'], h['network'], h['description'], h['id']), response_query_str))
    return list(set(response_query))  # REMOVE DUPLICATES


def select_mac_all_hosts(lock: Lock) -> Tuple[Text, ...]:
    query: Text = "SELECT Hosts.mac FROM Hosts group by Hosts.mac ORDER BY Hosts.mac;"
    response_query: List[Tuple[Text, ...]] = conection_sqlite(DB, query, is_dict=False, mutex=lock)
    return tuple(i[0] for i in response_query)


def select_hosts_online(lock: Lock) -> List[Host]:
    query: Text = "SELECT Hosts.* FROM Hosts WHERE Hosts.date IN (SELECT Datetime.date FROM Datetime LIMIT 1) ORDER BY Hosts.id DESC;"
    response_query_str: List[Dict[Text, Any]] = conection_sqlite(DB, query, is_dict=True, mutex=lock)
    return get_list_host(response_query_str)


def select_hosts_offline(lock: Lock) -> List[Host]:
    query: Text = "SELECT Hosts.* FROM Hosts WHERE Hosts.date NOT IN (SELECT Datetime.date FROM Datetime LIMIT 1) ORDER BY Hosts.id DESC;"
    response_query_str: List[Dict[Text, Any]] = conection_sqlite(DB, query, is_dict=True, mutex=lock)
    return get_list_host(response_query_str)


def update_date(date: Text, lock: Lock) -> NoReturn:
    query: Text = f"UPDATE Datetime SET date='{date}' WHERE id LIKE 1;"
    logger.debug(query)
    conection_sqlite(DB, query, mutex=lock)


def insert_host(host: Host, lock: Lock) -> NoReturn:
    query: Text = f"INSERT INTO Hosts(ip, mac, vendor, description, date, network) VALUES ('{host.ip}'," \
                  f"'{host.mac}', '{host.vendor}','{host.description}','{host.date}','{host.network}');"
    logger.debug(query)
    conection_sqlite(DB, query, mutex=lock)


def update_host(host: Host, lock: Lock) -> NoReturn:
    query: Text = f"UPDATE Hosts SET ip='{host.ip}', mac='{host.mac}', vendor='{host.vendor}', date='{host.date}', " \
                  f"network='{host.network}' WHERE ip LIKE '{host.ip}';"
    logger.debug(query)
    conection_sqlite(DB, query, mutex=lock)


def check_database() -> NoReturn:
    """
    Comprueba si existe la base de datos, sino existe la crea
    :return:
    """
    try:
        query: Text = "SELECT * FROM Hosts"
        conection_sqlite(DB, query)
    except OSError:
        logger.info(f'the database {DB} doesn\'t exist, creating it with the default configuration')
        execute_script_sqlite(DB, DB_STRUCTURE.read_text())


if __name__ == '__main__':
    nlock: Lock = Lock()
    (select_hosts_offline(nlock))
    select_hosts_online(nlock)
    select_mac_all_hosts(nlock)
