#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from pathlib import Path  # nueva forma de trabajar con rutas
from threading import Lock
from typing import List, Text, NoReturn, Tuple, Any, Dict

from procamora_utils.interface_sqlite import conection_sqlite, execute_script_sqlite
from procamora_utils.logger import get_logging, logging

from host import Host

logger: logging = get_logging(False, 'sqlite')

# Ruta absoluta de la BD
DB: Path = Path(Path(__file__).resolve().parent, "database.db")
DB_STRUCTURE: Path = Path(Path(__file__).resolve().parent, "database.db.sql")


def get_list_host(response_query_str: List[Dict[Text, Any]]):
    if response_query_str is None:
        return list()
    response_query: List[Host] = list(
        map(lambda h: Host(h['ip'], h['mac'], h['vendor'], h['date'], h['network'], h['description'], h['id']), response_query_str))
    return sorted(list(set(response_query)))  # REMOVE DUPLICATES


def select_mac_all_hosts(lock: Lock) -> Tuple[Text, ...]:
    query: Text = "SELECT Hosts.mac FROM Hosts group by Hosts.mac ORDER BY Hosts.mac;"
    response_query: List[Tuple[Text, ...]] = conection_sqlite(DB, query, is_dict=False, mutex=lock)
    return tuple(i[0] for i in response_query)


def select_hosts_online(lock: Lock) -> List[Host]:
    """
   Filtramos por los hosts cuya fecha de actualizacion coincida con la fecha de la tabla datetime que registra
   el ultimo escaneo realizado.
    """
    query: Text = \
"""SELECT h.*, d.description
FROM Hosts as h
LEFT JOIN Description as d ON h.mac = d.mac
WHERE h.date IN (SELECT Datetime.date FROM Datetime LIMIT 1) 
ORDER BY h.id DESC;"""
    response_query_str: List[Dict[Text, Any]] = conection_sqlite(DB, query, is_dict=True, mutex=lock)
    return get_list_host(response_query_str)


def select_hosts_offline(lock: Lock) -> List[Host]:
    """
    Para seleccionar los hosts offline, lo que se hace es descartar los online:
    1. Seleccionamos la tabla hosts ordenandola descendentemente por id para que al agrupar obtendamos los ids mayores.
    2. Filtramos aquellos hosts que tienen la fecha como la ultima actualizacion, ya que estos estan online.
    3. Agrupamo por mac para eliminar hosts duplicados.
    """
    query: Text = \
"""SELECT h.*, d.description
FROM (SELECT * FROM Hosts ORDER BY id DESC) as h
LEFT JOIN Description as d ON h.mac = d.mac
WHERE h.mac NOT IN (
		SELECT h2.mac
		FROM Hosts as h2
		WHERE h2.date IN (SELECT Datetime.date FROM Datetime LIMIT 1) 
)
GROUP BY h.mac"""
    response_query_str: List[Dict[Text, Any]] = conection_sqlite(DB, query, is_dict=True, mutex=lock)

    return get_list_host(response_query_str)


def update_date(date: Text, lock: Lock) -> NoReturn:
    query: Text = f"UPDATE Datetime SET date='{date}' WHERE id LIKE 1;"
    logger.debug(query)
    conection_sqlite(DB, query, mutex=lock)


def insert_host(host: Host, lock: Lock) -> NoReturn:
    query: Text = f"INSERT INTO Hosts(ip, mac, vendor, date, network) VALUES ('{host.ip}'," \
                  f"'{host.mac}', '{host.vendor}','{host.date}','{host.network}');"
    logger.debug(query)
    conection_sqlite(DB, query, mutex=lock)
    
    # insert description if not exist mac in table description
    query: Text = \
f"""INSERT INTO Description(mac, description)
SELECT * FROM (SELECT '{host.mac}', '')
WHERE NOT EXISTS (
    SELECT mac FROM Description WHERE mac = '{host.mac}'
) LIMIT 1;"""
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
    print(select_hosts_offline(nlock))
    print(select_hosts_online(nlock))
    print(select_mac_all_hosts(nlock))
    


