#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import tempfile
from typing import Text, NoReturn, List

from fpdf import FPDF


# http://www.blog.pythonlibrary.org/2018/06/05/creating-pdfs-with-pyfpdf-and-python/


class CustomPDF(FPDF):

    def header(self: CustomPDF) -> NoReturn:
        # Set up a logo
        self.image('icons/profile.png', 10, 8, 33)
        self.set_font('Arial', 'B', 14)

        # Add an address
        self.cell(100)
        self.cell(0, 5, 'procamora', ln=1)
        self.cell(100)
        self.cell(0, 5, 'pablojoserocamora@gmail.com', ln=1)
        self.cell(100)
        self.cell(0, 5, 'bot_scan_networks', ln=1)

        # Line break
        self.ln(20)

    def footer(self: CustomPDF) -> NoReturn:
        self.set_y(-10)

        self.set_font('Arial', 'I', 8)

        # Add a page number
        page = 'Page ' + str(self.page_no()) + '/{nb}'
        self.cell(0, 10, page, 0, 0, 'C')


def create_pdf(pdf_path: Text, spacing: int = 1):
    header_table: List = ['IP', 'MAC', 'ACTIVE', 'VENDOR', 'DESCRIPTION', 'NETWORK']
    data = [
        ['Mike', 'Driscoll', 'mike@somewhere.com', '55555'],
        ['John', 'Doe', 'jdoe@doe.com', '12345'],
        ['Nina', 'Ma', 'inane@where.com', '54321']
    ]
    table = list()
    table.append(header_table)
    table.append(data[0])
    print(table)

    pdf: CustomPDF = CustomPDF(orientation='P', unit='mm', format='A4')
    # Create the special value {nb}
    pdf.alias_nb_pages()  # numero de paginas
    pdf.add_page()
    pdf.set_font('Times', '', 12)

    col_width: int = pdf.w / 6.5
    row_height: int = pdf.font_size
    for row in table:
        for item in row:
            pdf.cell(col_width, row_height * spacing,
                     txt=item, border=1)
        pdf.ln(row_height * spacing)

    pdf.output(pdf_path)


if __name__ == '__main__':
    fp: tempfile._TemporaryFileWrapper = tempfile.NamedTemporaryFile()
    print(fp.name)
    os.system(f'ls -la {fp.name}')
    create_pdf(fp.name)
    os.system(f'ls -la {fp.name}')
    fp.close()
    os.system(f'ls -la {fp.name}')
