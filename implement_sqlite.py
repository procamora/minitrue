#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import logging
from pathlib import Path  # nueva forma de trabajar con rutas
from typing import List, Text, NoReturn, Tuple

from procamora_utils.interface_sqlite import conection_sqlite, execute_script_sqlite
from procamora_utils.logger import get_logging

from host import Host

logger: logging = get_logging(False, 'sqlite')

# Ruta absoluta de la BD
DB: Path = Path(Path(__file__).resolve().parent, "database.db")
DB_STRUCTURE: Path = Path(Path(__file__).resolve().parent, "database.db.sql")


def select_all_hosts() -> Tuple[Text, ...]:
    query: Text = "SELECT Hosts.mac FROM Hosts group by Hosts.mac ORDER BY Hosts.mac;"
    response_query: List[Tuple[Text, ...]] = conection_sqlite(DB, query, is_dict=False)
    return tuple(i[0] for i in response_query)


def select_hosts_online() -> List[Tuple[Text, ...]]:
    query: Text = "SELECT Hosts.* FROM Hosts WHERE Hosts.date IN (SELECT Datetime.date FROM Datetime LIMIT 1);"
    response_query: List[Tuple[Text, ...]] = conection_sqlite(DB, query, is_dict=False)
    return response_query


def select_hosts_offline() -> List[Tuple[Text, ...]]:
    query: Text = "SELECT Hosts.* FROM Hosts WHERE Hosts.date NOT IN (SELECT Datetime.date FROM Datetime LIMIT 1);"
    response_query: List[Tuple[Text, ...]] = conection_sqlite(DB, query, is_dict=False)
    return response_query


def update_date(date: Text) -> NoReturn:
    query: Text = f"UPDATE Datetime SET date='{date}' WHERE id LIKE 1;"
    logger.debug(query)
    conection_sqlite(DB, query)


def insert_host(host: Host) -> NoReturn:
    query: Text = f"INSERT INTO Hosts(ip, mac, vendor, description, date, network) VALUES ('{host.ip}'," \
                  f"'{host.mac}', '{host.vendor}','{host.description}','{host.date}','{host.network}');"
    logger.debug(query)
    conection_sqlite(DB, query)


def update_host(host: Host) -> NoReturn:
    query: Text = f"UPDATE Hosts SET ip='{host.ip}', mac='{host.mac}', vendor='{host.vendor}', date='{host.date}', " \
                  f"network='{host.network}' WHERE ip LIKE '{host.ip}';"
    logger.debug(query)
    conection_sqlite(DB, query)


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

