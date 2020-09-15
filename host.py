#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import Text, NoReturn, Dict, Any


@dataclass
class Host:
    ip: Text
    mac: Text
    vendor: Text
    date: Text
    network: Text
    description: Text = str()
    id: int = -1

    def __post_init__(self: Host)-> NoReturn:
        self.mac = self.mac.lower()

    def __eq__(self: Host, other: Host) -> bool:
        if not isinstance(other, Host):
            return False
        return self.ip == other.ip and self.mac == other.mac and self.network == other.network

    def __hash__(self: Host) -> int:
        filter_dict: Dict[Text, Any] = self.__dict__.copy()
        filter_dict.pop('id')
        filter_dict.pop('date')
        return hash(tuple(map(str, filter_dict.values())))
        #return hash((self.ip, self.mac, self.vendor, self.network))
        
    def __lt__(self: Host, other: Host):
        # Si no definimos esta funcion tambien podemos ordenar por:
        # sorted(list_hosts, key=lambda h: h.ip, reverse=False) 
        if self.ip == other.ip:
            return self.mac < other.mac
        return self.ip < other.ip
