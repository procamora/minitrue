#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ipaddress
import subprocess
from ipaddress import IPv4Interface, IPv6Interface
from typing import List, Optional, Tuple, Union, Dict, Text

import netifaces
import nmap
from mac_vendor_lookup import MacLookup

from host import Host
from implement_sqlite import select_all_hosts, insert_host, update_host, update_host_offline, logger


class ScanNmap:
    def __init__(self, subnets: List[Union[IPv4Interface, IPv6Interface]] = None):
        self.local_interfaces: Dict[Text, Text] = dict()
        self.subnets: List[Union[IPv4Interface, IPv6Interface]] = list()
        self.hosts_db: Dict[Text, Host] = dict()
        self.vendor = MacLookup()
        self.vendor.load_vendors()

        self.set_local_interfaces()
        if subnets is None:  # Si añado las interfaces manualmente, no las busco
            self.set_ip_interfaces()
        else:
            self.subnets = subnets
        self.hosts_db = select_all_hosts()
        logger.info(self.subnets)

    def set_local_interfaces(self: ScanNmap):
        """
        Metodo para obtener todas las interfaces del sistema que tienen asignada una direccion IP y enlazarla con su MAC
        en un diccionario
        :return:
        """
        for i in netifaces.interfaces():
            addrs = netifaces.ifaddresses(i)
            if netifaces.AF_INET in addrs and netifaces.AF_LINK in addrs:
                self.local_interfaces[addrs[netifaces.AF_INET][0]['addr']] = addrs[netifaces.AF_LINK][0]['addr']

    def set_ip_interfaces(self: ScanNmap):
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

    def get_mac_aux(self: ScanNmap, ip: Text) -> Text:
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

    def ping_scan(self: ScanNmap, subnet: Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]) -> List[Host]:
        hosts: List[Host] = list()
        nm: nmap.nmap.PortScanner = nmap.PortScanner()
        scan: Dict = nm.scan(hosts=str(subnet), arguments='-n -sP', sudo=False)
        print(nm.command_line())

        ip: Text
        for ip in nm.all_hosts():
            t: nmap.nmap.PortScannerHostDict = nm[ip]
            ip = t["addresses"]["ipv4"]

            if 'mac' not in t["addresses"]:
                mac = self.get_mac_aux(ip)
            else:
                mac = t["addresses"]["mac"]

            if len(t["vendor"]) == 0:
                # desc = MacLookup().lookup(mac)
                vend = self.vendor.lookup(mac)
            else:
                vend = t["vendor"]

            host: Host = Host(ip, mac, True, vend, scan["nmap"]["scanstats"]["timestr"], subnet.network)
            logger.debug(f'detect: {host}')
            hosts.append(host)

        return hosts

    def update_or_insert_host(self: ScanNmap, hosts: List[Host]):
        host: Host
        for host in hosts:
            if host.ip in self.hosts_db.keys():
                logger.debug(f'update {host}')
                update_host(host)
            else:
                insert_host(host)
                logger.warning(f'new host: {host}')

    def run(self: ScanNmap):
        subnet: Union[IPv4Interface, IPv6Interface]
        for subnet in self.subnets:
            logger.info(f'Scanning: {subnet}')
            hosts: List[Host] = self.ping_scan(subnet)
            self.update_or_insert_host(hosts)
            # FIXME plantear otro diseño, su hay varias interfaces pondria el del resto como inactivos
            # subnet_partial = re.sub(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', r'\1.\2.\3.', str(subnet.ip))
            update_host_offline(hosts[0].date, hosts[0].network)

    @staticmethod
    def format_text(param_text: bytes) -> Optional[Text]:
        if param_text is not None:
            text = param_text.decode('utf-8')
            return str(text)
        return param_text

    @staticmethod
    def execute_command(command: Text) -> Tuple[Text, Text, subprocess.Popen]:
        # FIXME CAMBIAR Popen por run
        execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = execute.communicate()
        return ScanNmap.format_text(stdout), ScanNmap.format_text(stderr), execute


def main():
    l: list = [ipaddress.ip_interface('192.168.1.0/24')]
    a = ScanNmap(l)
    a.run()


if __name__ == '__main__':
    main()

# https://github.com/maaaaz/nmaptocsv

# ENVIAR UN MSG CON LAS IPs DE LAS INTERFACES
