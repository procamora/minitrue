#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import logging
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Text, Tuple, Any, Optional, List, IO

import jinja2
from procamora_utils.logger import get_logging

from host import Host

logger: logging = get_logging(False, 'pdf')


def generate_latex(hosts_online: List[Host], hosts_offline: List[Host], interfaces: Text, arp: Text, routes: Text) \
        -> Text:
    working_path: Path = Path(__file__).resolve().parent
    # report_path: Path = Path(working_path, 'resources', 'templates', 'report.tex')
    personal_icon_path: Path = Path(working_path, 'resources', 'images', 'personal.png')
    proyect_icon_path: Path = Path(working_path, 'resources', 'images', 'logo_transparent.png')
    template_latex_path: Path = Path('resources/templates/report.tex')

    latex_jinja_env = jinja2.Environment(
        block_start_string=r'\BLOCK{',
        block_end_string='}',
        variable_start_string=r'\VAR{',
        variable_end_string='}',
        comment_start_string=r'\#{',
        comment_end_string='}',
        line_statement_prefix='%%',
        line_comment_prefix='%#',
        trim_blocks=True,
        autoescape=False,
        loader=jinja2.FileSystemLoader(str(working_path))
    )

    now = datetime.now()  # current date and time
    template: jinja2.environment.Template = latex_jinja_env.get_template(str(template_latex_path))

    title_pdf = r'\href{https://telegram.me/procamora_scan_bot}{procamora_scan_bot}'

    try:
        latex_generate = template.render(date=now.strftime("%m/%d/%Y"), title=title_pdf, author='minitrue', hosts_online=hosts_online,
                                         hosts_offline=hosts_offline, icon1=str(personal_icon_path), icon2=str(proyect_icon_path),
                                         interfaces=interfaces, arp=arp, routes=routes)
    except jinja2.exceptions.UndefinedError as e:
        logger.critical(f'Error in jinja.rende: {e}')
        sys.exit(0)
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
    file_data: IO = response.open('rb')

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
    out, err = execute.communicate()
    return format_text(out), format_text(err), execute


def main():
    from implement_sqlite import select_hosts_online, select_hosts_offline
    online: List[Host] = select_hosts_online(None)
    offline: List[Host] = select_hosts_offline(None)
    
    cmd_interfaces: Text = 'ip address show'
    stdout_interfaces, stderr, ex = execute_command(cmd_interfaces)

    cmd_arp: Text = 'ip neigh show'
    stdout_arp, stderr, ex = execute_command(cmd_arp)

    cmd_routes: Text = 'ip route list'
    stdout_routes, stderr, ex = execute_command(cmd_routes)

    string_latex = generate_latex(online, offline, stdout_interfaces, stdout_arp, stdout_routes)
    latex_to_pdf(string_latex)


if __name__ == '__main__':
    main()
