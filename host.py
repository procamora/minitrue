#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import Text


@dataclass
class Host:
    ip: Text
    mac: Text
    vendor: Text
    date: Text
    network: Text
    description: Text = str()
    id: int = -1

    def __post_init__(self: Host):
        self.mac = self.mac.lower()

    def __eq__(self: Host, other: Host):
        return self.ip == other.ip and self.mac == other.mac and self.network == other.network

    def __hash__(self: Host) -> int:
        return hash((self.ip, self.mac, self.vendor, self.network))
