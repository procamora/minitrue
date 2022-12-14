#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse  # https://docs.python.org/3/library/argparse.html
import datetime
import logging
import sys
from base64 import b64decode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, NoReturn, Text, Tuple

from bs4 import BeautifulSoup
from gvm.connections import TLSConnection
from gvm.protocols.latest import Gmp
#from gvm.protocols.gmpv7 import Gmp  # https://github.com/greenbone/python-gvm/issues/182
from gvm.xml import pretty_print
from lxml import etree
from procamora_utils.ip import IP
from procamora_utils.logger import get_logging

logger: logging = get_logging(True, 'openvas')

FULL_FAST: Text = 'daba56c8-73ec-11df-a475-002264764cea'
FULL_FAST_ULT: Text = 'daba56c8-73ec-11df-a475-002264764cea'
FULL_DEEP: Text = '708f25c4-7489-11df-8094-002264764cea'
FULL_DEEP_ULT: Text = '74db13d6-7489-11df-91b9-002264764cea'


def create_arg_parser() -> argparse:
    """
    Metodo para establecer los argumentos que necesita la clasek
    :return:
    """
    example = "python3 %(prog)s -t 127.0.0.1"

    my_parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='%(prog)s a is a script for managing openvas using the console',
        usage='{}'.format(example))

    openvas_group = my_parser.add_argument_group('openvas arguments')
    openvas_group.add_argument('--host', default='127.0.0.1', help='IP address where the OpenVas service is located.')
    openvas_group.add_argument('-u', '--user', default='admin', help='OpenVas user.')
    openvas_group.add_argument('-p', '--password', default='admin', help='OpenVas password.')
    openvas_group.add_argument('-t', '--target', help='Target host to be analyzed.')
    openvas_group.add_argument('--type', default='74db13d6-7489-11df-91b9-002264764cea', help='scan type.')
    openvas_group.add_argument('--ports', default=None, help='scan ports TCP (example tcp: "T: 22,80,443").')

    report_group = my_parser.add_argument_group('report arguments')
    report_group.add_argument('-f', '--format', help='Report output format (PDF, LATEX, XML or HTML).')
    report_group.add_argument('--id', help='ID of the report to be exported.')
    report_group.add_argument('-l', '--list', action='store_true', default=False, help='List the reports generated.')

    my_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose flag (boolean).', default=False)

    if len(sys.argv) == 1:
        my_parser.print_help()
        sys.exit(0)

    return my_parser.parse_args()


@dataclass
class OpenVas:
    hostname: IP
    user: Text
    password: Text
    REGEX_ID = r'id=\"(.*)\"'
    file_log: Path = Path('./scans.log')
    export: Dict[Text, Text] = field(default_factory=dict)
    gmp: Gmp = None

    def __post_init__(self: OpenVas) -> NoReturn:
        connection: TLSConnection = TLSConnection(hostname=self.hostname.get_addr(), timeout=5)
        self.gmp = Gmp(connection)
        try:
            response: Text = self.gmp.authenticate(self.user, self.password)
            soup: BeautifulSoup = BeautifulSoup(response, 'xml')
            if int(soup.authenticate_response['status']) != 200:
                # logger.debug(soup.authenticate_response.attrs)
                self.print_and_exit(soup.authenticate_response['status_text'])
        except OSError:
            self.print_and_exit(f"Timeout connect Openvas {self.hostname.get_addr()}")

        self.export = {
            'PDF': 'c402cc3e-b531-11e1-9163-406186ea4fc5',
            'XML': 'a994b278-1f62-11e1-96ac-406186ea4fc5',
            'LATEX': 'a684c02c-b531-11e1-bdc2-406186ea4fc5',
            'HTML': '6c248850-1f62-11e1-b082-406186ea4fc5'
        }

    def get_version(self: OpenVas) -> NoReturn:
        # Retrieve current GMP version
        version = self.gmp.get_version()
        # Prints the XML in beautiful form
        pretty_print(version)

    def analize_ip(self: OpenVas, ipaddress: IP, scan_config_id: Text, ports: Text) -> Text:
        """
        Metodo para crear un target, crear una tarea para ese target con un tipo de scanner y ejecutar la tarea
        :type ipaddress: IP
        :param ipaddress:
        :param scan_config_id:
        :param ports:
        :return:
        """
        target_id: Text = self._create_target(ipaddress.get_addr(), ports)
        if target_id is None:
            self.print_and_exit("create_target failed")

        # full_and_fast_scan_config_id = 'daba56c8-73ec-11df-a475-002264764cea'
        openvas_scanner_id: Text = '08b69003-5fc2-4037-a479-93b440211c73'

        name_task: Text = f'Python Scan Host {ipaddress.get_addr()}'
        task_id: Text = self._create_task(name_task, target_id, scan_config_id, openvas_scanner_id)
        if task_id is None:
            self.print_and_exit("create_task failed")

        report_id: Text = self._start_task(task_id)

        string: Text = f'Started scan of host {ipaddress.get_addr()} - Corresponding report ID is {report_id}\n'
        logger.info(string)
        with open(str(self.file_log), 'a') as f:
            f.write(string)
        return report_id

    def _create_target(self: OpenVas, ip_address: Text, ports: Text) -> Optional[Text]:
        """
        Metodo privado para crear un target para una direccion IP proporcionada
        :param ip_address:
        :param ports:
        :return:
        """
        # create a unique name by adding the current datetime
        name: Text = f'Python Host {ip_address} {str(datetime.datetime.now())}'
        response: Text = self.gmp.create_target(name=name, hosts=[ip_address], port_range=ports)
        return self._get_id(response)

    def _create_task(self: OpenVas, name: Text, target_id: Text, scan_config_id: Text, scanner_id: Text) -> \
            Optional[Text]:
        """
        Metodo para crear una tarea para un target proporcionado y con una serie de configuraciones
        :param target_id:
        :param scan_config_id:
        :param scanner_id:
        :return:
        """
        response: Text = self.gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id,
                                              scanner_id=scanner_id, comment="automatic task")
        return self._get_id(response)

    def _start_task(self: OpenVas, task_id: Text) -> Optional[Text]:
        """
        Metodo para iniciar una tarea a traves del id
        :param task_id:
        :return:
        """
        response = self.gmp.start_task(task_id)
        # the response is <start_task_response><report_id>id</report_id></start_task_response>
        logger.debug('response: ' + response)
        soup: BeautifulSoup = BeautifulSoup(response, 'xml')
        return soup.contents[0].string  # No se porque pero contiene valor de report_id
        # regex = r'<report_id>(.*)</report_id>'
        # if re.search(regex, response):
        #    return re.search(regex, response).group(1)
        # return None

    @staticmethod
    def _get_id(response: Text) -> Optional[Text]:
        logger.debug('response: ' + response)
        soup: BeautifulSoup = BeautifulSoup(response, 'xml')
        # logger.debug(soup.contents[0].attrs)
        # como solo hay un elemento en el xml se obtiene y se accede al atributo id
        return soup.contents[0]['id']

        # if re.search(self.REGEX_ID, response):
        #    return re.search(self.REGEX_ID, response).group(1)
        # return None

    def report(self: OpenVas, report_id, report_type: Text, directory: Path = Path('./')) -> Path:
        report_type = report_type.upper()
        if report_type not in self.export.keys():
            logger.critical(f"Format {report_type} is not compatible, use: PDF, HTML, XML or LATEX")
            sys.exit(1)

        if report_type == 'LATEX':
            return self.report_aux(report_id, report_type, 'tex', directory)
        else:
            return self.report_aux(report_id, report_type, report_type, directory)

    def report_aux(self: OpenVas, report_id: Text, param_type: Text, extension: Text, directory: Path) -> Path:
        response = self.gmp.get_report(report_id=report_id, report_format_id=self.export[param_type])
        response_xml = etree.fromstring(response)  # conversion de objeto str a xml
        if not self.is_response_valid(response_xml):
            raise ValueError('Could not process XML')

        # uso regex porque es mas facil que trabajar con el xml
        # regex que obtiene el reporte en texto plano para convertirlo al formato deseado
        # logger.info(response)

        soup: BeautifulSoup = BeautifulSoup(response, 'xml')
        # El ultimo elemento de report es el que contiene el codigo
        content = soup.contents[0].find('report').contents[-1]

        # regex = rf'<report_format id=\"(.*)\"><name>{param_type}</name></report_format>(.*)</report>'
        # re.S es necesario para el formato xml ya que tiene saltos de linea
        # content: Text = re.search(regex, response, re.IGNORECASE | re.S).group(2)
        pdf_path = Path(directory, f'{report_id}.{extension.lower()}').expanduser()

        if param_type == "XML":
            # Se guarda como texto en vez de binario
            pdf_path.write_text(content)
            logger.debug(f"Done. {param_type} created: {pdf_path}")
            return pdf_path

        # convert content to 8-bit ASCII bytes
        binary_base64_encoded_pdf = content.encode('ascii')
        # decode base64
        binary_pdf = b64decode(binary_base64_encoded_pdf)
        # write to file and support ~ in filename path
        pdf_path.write_bytes(binary_pdf)

        logger.debug(f'Done. {param_type} created: {pdf_path}')
        return pdf_path

    @staticmethod
    def is_response_valid(response) -> bool:
        """
        Funcion que comprueba si la respuesta del reporte es correcta
        :param response:
        :return:
        """
        if int(response.get("status")) == 200:
            return True

        logger.critical(response.get("status_text"))
        return False

    def list_tasks(self) -> Dict[Text, Tuple[Text, int, float]]:
        response = self.gmp.get_tasks()
        response_xml = etree.fromstring(response)

        message: Dict[Text, Tuple[Text, int, float]] = dict()
        logger.debug("List of reports")
        for task in response_xml.xpath('task'):
            id_report: Text = str()
            last_report = task.find("last_report/report")
            if last_report is not None:
                id_report = last_report.get("id")
            else:
                last_report = task.find("current_report/report")
                if last_report is not None:
                    id_report = last_report.get("id")

            name: Text = task.find("name").text
            progress: int = int(task.find("progress").text)
            if progress == -1:
                progress = 100
            # si no hay reporte falla al intentar obtener el ultimo
            severity_find = task.find("last_report/report/severity")
            severity: int
            if severity_find is not None:
                severity = severity_find.text
            else:
                severity = -1

            logger.debug(f'id: {id_report}, name: {name}, progress: {progress}%, severity: {severity}')
            message[id_report] = (name, progress, severity)

        return message

    @staticmethod
    def print_and_exit(message: Text, code: int = 1) -> NoReturn:
        logger.critical(message)
        sys.exit(code)


if __name__ == '__main__':
    args = create_arg_parser()

    openvas: OpenVas = OpenVas(IP(ip=args.host), args.user, args.password)

    if args.target:
        ip = IP(ip=args.target)
        openvas.analize_ip(ip, args.type, args.ports)
    elif args.format and args.id:
        # report_id = '9331a947-2a02-4979-8933-ddea8bb2bbd7'
        openvas.report(args.id, args.format)
    elif args.list:
        openvas.list_tasks()
    else:
        logger.info("Arguments is necesary")

        sys.exit(0)

    # pdf_report_format_id = "1a60a67e-97d0-4cbf-bc77-f71b08e7043d"
