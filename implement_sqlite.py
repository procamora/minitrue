#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import logging
import sqlite3
from pathlib import Path  # nueva forma de trabajar con rutas
from typing import Dict, Any, List, Text, NoReturn

from procamora_logging import get_logging
from procamora_sqlite3 import conection_sqlite

from host import Host

logger: logging = get_logging(True, 'sqlite')

# Ruta absoluta de la BD
DB: Path = Path(Path(__file__).resolve().parent, "database.db")


def select_all_hosts() -> Dict[Text, Host]:
    query: Text = "SELECT * FROM Hosts"
    response_query: List[Dict[Text, Any]] = conection_sqlite(DB, query, is_dict=True)
    response: Dict[Text, Host] = dict()
    for i in response_query:
        active: bool = bool(int(i['active']))  # La conversion a bool se hace con un int no con str
        host: Host = Host(i['ip'], i['mac'], active, i['vendor'], i['date'], i['network'], i['description'], i['id'])
        response[host.ip] = host
    return response


def select_hosts_online() -> List[List[Text]]:
    query: Text = "SELECT ip, vendor FROM Hosts WHERE active LIKE 1"
    response_query: List[List[Text]] = conection_sqlite(DB, query, is_dict=False)
    return response_query


def select_hosts_offline() -> List[List[Text]]:
    query: Text = "SELECT ip, vendor FROM Hosts WHERE active LIKE 0"
    response_query: List[List[Text]] = conection_sqlite(DB, query, is_dict=False)
    return response_query


def insert_host(host: Host) -> NoReturn:
    # active es in integer en la BD 0 (false) and 1 (true). Si se inserta es porque esta activo
    # >> > int(True == True)
    # 1
    # >> > int(False == True)
    # 0
    active: int = int(host.active == True)
    # INSERT OR REPLACE INTO
    query: Text = f"INSERT INTO Hosts(ip, mac, active, vendor, description, date, network) VALUES ('{host.ip}'," \
                  f"'{host.mac}', {active}, '{host.vendor}','{host.description}','{host.date}','{host.network}');"
    logger.debug(query)
    # TODO chapuza temporal, si falla al insertar es que ya existe y hay que actualizar. Compronar si existe antes
    # de intentar insertar de primeras
    try:
        conection_sqlite(DB, query)
    except sqlite3.IntegrityError as e:
        logger.critical(e)
        update_host(host)


def update_host(host: Host) -> NoReturn:
    active: int = int(host.active == True)
    query: Text = f"UPDATE Hosts SET ip='{host.ip}', mac='{host.mac}', vendor='{host.vendor}', date='{host.date}', " \
                  f"active={active}, network='{host.network}' WHERE ip LIKE '{host.ip}';"
    logger.debug(query)
    conection_sqlite(DB, query)


def update_host_offline(date: Text, network: Text):
    """
    Metodo que pone inactivo todos aquellos host que no se hayan actualizado con el ultimo escaneo
    :param date:
    :param network:
    :return:
    """
    query: Text = f"UPDATE Hosts SET active=0 WHERE date <> '{date}' AND network LIKE '{network}';"
    logger.debug(query)
    conection_sqlite(DB, query)
