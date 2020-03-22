#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Text, Tuple, Any

from host import Host


def generate_latex(hosts: Dict[Text, Host]) -> Text:
    import jinja2
    import os
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
        loader=jinja2.FileSystemLoader(os.path.abspath('.'))
    )

    now = datetime.now()  # current date and time
    template = latex_jinja_env.get_template('template.tex')
    latex_generate = template.render(date=now.strftime("%m/%d/%Y"), title='report', author='asdasd', hosts=hosts)
    return latex_generate


def latex_to_pdf(code_latex) -> Tuple[subprocess.CompletedProcess, Any]:
    fp: tempfile._TemporaryFileWrapper = tempfile.NamedTemporaryFile(prefix='report_', suffix='.tex')
    file_tex = Path(fp.name)
    file_tex.write_text(code_latex)

    dir_temp: tempfile.TemporaryDirectory = tempfile.TemporaryDirectory(prefix='latex_')

    command = f'pdflatex -output-directory={dir_temp.name} -interaction=nonstopmode {str(file_tex)}'
    print(command)
    execute: subprocess.CompletedProcess = subprocess.run(command.split(' '), stdout=subprocess.PIPE,
                                                          stderr=subprocess.PIPE)
    response = Path(dir_temp.name, file_tex.name.replace(".tex", ".pdf"))
    file_data = open(str(response), 'rb')
    print(type(file_data))

    print(execute.returncode)
    fp.close()
    return execute, file_data


if __name__ == '__main__':
    aaaaaaa = {
        '192.168.1.1': Host(ip='192.168.1.1', mac='d0:6e:de:51:6d:e3', active=True, vendor='Sagemcom Broadband SAS',
                            date='Sun Mar 22 00:04:08 2020', network='192.168.1.0/24', description='', id=1),
        '192.168.1.131': Host(ip='192.168.1.131', mac='b4:9d:0b:72:be:93', active=True, vendor='BQ',
                              date='Sun Mar 22 00:04:08 2020', network='192.168.1.0/24', description='', id=12),
        '192.168.1.42': Host(ip='192.168.1.42', mac='80:32:53:81:5d:08', active=False, vendor='Intel Corporate',
                             date='Sat Mar 21 01:13:24 2020', network='192.168.1.0/24', description='', id=13)
    }

    a = generate_latex(aaaaaaa)
    latex_to_pdf(a)
    # fp: tempfile._TemporaryFileWrapper = tempfile.NamedTemporaryFile(prefix='report_', suffix='.pdf')
    # create_pdf_all_hosts('fp.name', aaaaaaa)
    # fp.close()
