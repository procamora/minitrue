#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ipaddress
import logging
import subprocess
import sys
from typing import List, Tuple, Dict, Text, NoReturn

import netifaces
import nmap
from procamora_utils.ip import IP
from procamora_utils.logger import get_logging
from procamora_utils.ping import ping

from host import Host
from implement_sqlite import select_all_hosts, insert_host, update_date, check_database
from mac_vendor_lookup_sync import MacLookup

logger: logging = get_logging(False, 'scan_nmap')


class ScanNmap:
    def __init__(self: ScanNmap, subnets: ipaddress.ip_interface = None) -> NoReturn:
        self.nmap_tcp_scan: Text = '--top-ports 1000 --open -T5 -sV -v -n'
        self.nmap_ping_scan: Text = '-n -sP'

        self.local_interfaces: Dict[Text, Text] = dict()
        self.subnets: List[ipaddress.ip_interface] = list()
        self.db_mac_hosts: Tuple[Text] = tuple()
        self.vendor = MacLookup()
        self.vendor.load_vendors()

        self._set_local_interfaces()
        if subnets is None or len(subnets) == 0:  # Si añado las interfaces manualmente, no las busco
            self._set_ip_interfaces()
        else:
            self.subnets = subnets
        self.update_db()
        logger.info(self.subnets)

    def update_db(self: ScanNmap) -> NoReturn:
        self.db_mac_hosts = select_all_hosts()
        logger.debug(self.db_mac_hosts)

    def _set_local_interfaces(self: ScanNmap) -> NoReturn:
        """
        Metodo para obtener todas las interfaces del sistema que tienen asignada una direccion IP y enlazarla con su MAC
        en un diccionario
        :return:
        """
        for i in netifaces.interfaces():
            addrs = netifaces.ifaddresses(i)
            if netifaces.AF_INET in addrs and netifaces.AF_LINK in addrs:
                self.local_interfaces[addrs[netifaces.AF_INET][0]['addr']] = addrs[netifaces.AF_LINK][0]['addr']

    def _set_ip_interfaces(self: ScanNmap):
        """
        Metodo para obtener las IP con las subred, uso este metodo en vez de utilizar el anterior por comodida, ya que
        de esta forma se obtiene la mascara en formato valido para pasarselo a nmap
        :return:
        """
        # Obtengo todas las interfaces, filtrando aquillas que no son globales (scope global)
        command: Text = 'ip addr | grep "inet" | grep -vE "scope host|scope link"'
        stdout, stderr, ex = ScanNmap.execute_command(command)
        if len(stderr) > 0:
            logger.error(f'{stderr}')

        for i in stdout.split('\n'):
            if len(i) > 0:
                interface = i.strip().split(' ')[1]
                subnet = ipaddress.ip_interface(interface)
                self.subnets.append(subnet)

    def _get_mac_aux(self: ScanNmap, ip: Text) -> Text:
        """
        Metodo para obtener del sistema la MAC asociada a una IP
        :param ip:
        :return:
        """
        # Si es una IP del propio sistema la devulvo directamente, ya que no esta en la tabla ARP
        if ip in self.local_interfaces.keys():
            return self.local_interfaces[ip]

        command: Text = f'ip neigh show | grep "{ip} dev"'
        stdout, stderr, ex = self.execute_command(command)
        if len(stderr) > 0:
            logger.error(f'{ip} -> {stderr}')
        return stdout.strip().split(' ')[4]

    def ping_subnet_scan(self: ScanNmap, subnet: ipaddress.ip_interface) -> List[Host]:
        """
        Metodo encargado de realizar el escaneo de una subred, retorna todos los hosts que encuentra
        :param subnet:
        :return:
        """
        hosts: List[Host] = list()
        nm: nmap.nmap.PortScanner = nmap.PortScanner()
        scan: Dict = nm.scan(hosts=str(subnet), arguments=self.nmap_ping_scan, sudo=False)
        logger.debug(nm.command_line())

        ip: Text
        for ip in nm.all_hosts():
            t: nmap.nmap.PortScannerHostDict = nm[ip]
            ip = t["addresses"]["ipv4"]

            if 'mac' not in t["addresses"]:
                mac = self._get_mac_aux(ip)
            else:
                mac = t["addresses"]["mac"]

            if len(t["vendor"]) == 0:
                # desc = MacLookup().lookup(mac)
                vend = self.vendor.lookup(mac)
            else:
                vend = t["vendor"]

            host: Host = Host(ip, mac, vend, scan["nmap"]["scanstats"]["timestr"], subnet.network)
            logger.debug(f'detect: {host}')
            hosts.append(host)

        return hosts

    def tcp_ip_scan(self: ScanNmap, param_ip: ipaddress.ip_interface) -> Tuple[Text, List[int]]:
        """
        Metodo encargado de realizar el escaneo a un host buscando servicios activos
        :param param_ip:
        :return:
        """
        nm: nmap.nmap.PortScanner = nmap.PortScanner()
        # sudo nmap --top-ports 1000 --open -T5 -sV -v -n 192.168.1.71
        nm.scan(hosts=str(param_ip), arguments=self.nmap_tcp_scan, sudo=True)
        logger.debug(nm.command_line())

        ip: nmap.nmap.PortScannerHostDict = nm[nm.all_hosts()[0]]
        ports: Text = f'#{param_ip}\n'
        list_ports: List[int] = list()
        logger.info(ip)
        for port in ip['tcp']:
            list_ports.append(int(port))
            service = ip['tcp'][port]
            ports += f'{port} ({service["name"]}): {service["product"]} (v{service["version"]})\n'
        return ports, list_ports

    def _insert_host(self: ScanNmap, hosts: List[Host]) -> List[Host]:
        """
        Metodo que se encarga de meter en la base de datos los host que se han encontrado en la red. Si ya esta en la
        bd actualiza la informacion y si no esta lo inserta. Retorna la lista de host que ha insertado en la bd
        :param hosts:
        :return:
        """
        host: Host
        response_host: List[Host] = list()

        if len(hosts) > 0:  # always update date scan
            update_date(hosts[0].date)

        for host in hosts:
            insert_host(host)
            if host.mac not in self.db_mac_hosts:
                logger.warning(f'new host: {host}')
                response_host.append(host)
        return response_host

    def run(self: ScanNmap) -> List[Host]:
        """
        Metodo encargado de recorrer todas las interfaces y realizar un escaneo en cada una de ellas. Retorna los nuevos
        hosts que se han encontrado
        :return:
        """
        subnet: ipaddress.ip_interface
        response_host: List[Host] = list()

        for subnet in self.subnets:
            logger.info(f'Scanning: {subnet}')

            valid: bool = True
            # Si ponemos IP valida (x.x.x.x/x) en vez de subred  ej: (x.x.x.0/x), comprobamos que la IP esta online
            # sino lo esta se omite, para evitar fallos de escritura y que  pierda tiempo escaneando la red
            if str(subnet) != str(subnet.network):
                valid = ping(IP(ip=str(subnet.ip)))
                logger.info(f'Scanning: {valid}')

            if valid:
                hosts: List[Host] = self.ping_subnet_scan(subnet)
                logger.debug(f'------> {hosts}')
                response_host += self._insert_host(hosts)
                # update_host_offline(hosts[0].date, hosts[0].network)
            else:
                logger.warning(f'{subnet} is skiped')
        return response_host

    @staticmethod
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

    @staticmethod
    def execute_command(command: Text) -> Tuple[Text, Text, subprocess.Popen]:
        """
        Metodo que realiza una llamada al sistema para ejecutar un comando
        :param command:
        :return:
        """
        # FIXME CAMBIAR Popen por run
        execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = execute.communicate()
        return ScanNmap.format_text(stdout), ScanNmap.format_text(stderr), execute


def main(args: List[Text]):
    check_database()
    list_networks: List[ipaddress.ip_interface] = list(map(lambda ip: ipaddress.ip_interface(ip), args))
    # mismo metodo pero mas legible :)
    # list_networks: List[ipaddress.ip_interface] = list()
    # for ip in args:
    #    list_networks.append(ipaddress.ip_interface(ip))

    a = ScanNmap(list_networks)
    print(a.run())


if __name__ == '__main__':
    # El [0] es el nombre del fichero
    main(sys.argv[1:])

