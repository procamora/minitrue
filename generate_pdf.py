#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import logging
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Text, Tuple, Any, Optional

import jinja2
from procamora_utils.logger import get_logging

from host import Host

logger: logging = get_logging(False, 'pdf')


def generate_latex(hosts: Dict[Text, Host], interfaces: Text, arp: Text, routes: Text) -> Text:
    working_path: Path = Path(__file__).resolve().parent
    # report_path: Path = Path(working_path, 'resources', 'templates', 'report.tex')
    personal_icon_path: Path = Path(working_path, 'resources', 'images', 'personal.png')
    proyect_icon_path: Path = Path(working_path, 'resources', 'images', 'logo_transparent.png')

    latex_jinja_env = jinja2.Environment(
        block_start_string='\BLOCK{',
        block_end_string='}',
        variable_start_string='\VAR{',
        variable_end_string='}',
        comment_start_string='\#{',
        comment_end_string='}',
        line_statement_prefix='%%',
        line_comment_prefix='%#',
        trim_blocks=True,
        autoescape=False,
        loader=jinja2.FileSystemLoader(str(working_path))
    )

    now = datetime.now()  # current date and time
    template: jinja2.environment.Template = latex_jinja_env.get_template('resources/templates/report.tex')

    title_pdf = r'\href{https://telegram.me/procamora_scan_bot}{procamora_scan_bot}'

    latex_generate = template.render(date=now.strftime("%m/%d/%Y"), title=title_pdf, author='asdasd', hosts=hosts,
                                     icon1=str(personal_icon_path), icon2=str(proyect_icon_path),
                                     interfaces=interfaces, arp=arp, routes=routes)
    return latex_generate


def latex_to_pdf(code_latex) -> Optional[Tuple[subprocess.CompletedProcess, Any]]:
    fp = tempfile.NamedTemporaryFile(prefix='report_', suffix='.tex')
    file_tex: Path = Path(fp.name)
    file_tex.write_text(code_latex)

    dir_temp: tempfile.TemporaryDirectory = tempfile.TemporaryDirectory(prefix='latex_')

    command = f'pdflatex -output-directory={dir_temp.name} -interaction=nonstopmode {str(file_tex)}'
    logger.debug(command)
    execute: subprocess.CompletedProcess = subprocess.run(command.split(' '), stdout=subprocess.PIPE,
                                                          stderr=subprocess.PIPE)
    if execute.returncode == 1:
        logger.error(execute.stdout.decode('utf-8'))
        return execute, None

    logger.info(f'returncode: {execute.returncode}')

    response = Path(dir_temp.name, file_tex.name.replace(".tex", ".pdf"))
    file_data = open(str(response), 'rb')

    ####################
    import time
    import os
    os.system(f'okular {str(response)}')
    time.sleep(20)

    #####################

    fp.close()
    return execute, file_data


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


if __name__ == '__main__':
    aaaaaaa = {
        '192.168.1.1': Host(ip='192.168.1.1', mac='00:00:00:00:00:00', active=True, vendor='Sagemcom Broadband SAS',
                            date='Sun Mar 22 00:04:08 2020', network='192.168.1.0/24', description='router', id=1),
        '192.168.1.131': Host(ip='192.168.1.31', mac='00:00:00:00:00:00', active=True, vendor='BQ',
                              date='Sun Mar 22 00:04:08 2020', network='192.168.1.0/24', description='movil1', id=12),
        '192.168.1.42': Host(ip='192.168.1.2', mac='00:00:00:00:00:00', active=False, vendor='Intel Corporate',
                             date='Sat Mar 21 01:13:24 2020', network='192.168.1.0/24', description='portatil1', id=13),
        '192.168.1.41': Host(ip='192.168.1.23', mac='00:00:00:00:00:00', active=False, vendor='Intel Corporate',
                             date='Sat Mar 21 01:13:24 2020', network='192.168.1.0/24', description='portatil2', id=13)
    }
    cmd_interfaces: Text = 'ip address show'
    stdout_interfaces, stderr, ex = execute_command(cmd_interfaces)

    cmd_arp: Text = 'ip neigh show'
    stdout_arp, stderr, ex = execute_command(cmd_arp)

    cmd_routes: Text = 'ip route list'
    stdout_routes, stderr, ex = execute_command(cmd_routes)

    string_latex = generate_latex(aaaaaaa, stdout_interfaces, stdout_arp, stdout_routes)
    execute, file = latex_to_pdf(string_latex)
