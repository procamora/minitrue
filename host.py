#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import Text


@dataclass
class Host():
    ip: Text
    mac: Text
    active: bool  # Es in integer en la BD 0 (false) and 1 (true).
    vendor: Text
    date: Text
    description: Text = str()
    id: int = int()
