#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import _io
import logging
import sys
from pathlib import Path
from typing import Text, NoReturn, Dict, AnyStr

import requests
from procamora_utils.logger import get_logging

logger: logging = get_logging(False, 'mac_lockup')

OUI_URL: Text = "http://standards-oui.ieee.org/oui.txt"


class InvalidMacError(Exception):
    pass


class BaseMacLookup(object):
    cache_path: Path = Path('~/.cache/mac-vendors2.txt').expanduser()

    @staticmethod
    def sanitise(_mac: Text) -> Text:
        mac: Text = _mac.replace(":", "").replace("-", "").upper()
        try:
            int(mac, 16)
        except ValueError:
            raise InvalidMacError(f"{_mac} contains unexpected character")
        if len(mac) > 12:
            raise InvalidMacError(f"{_mac} is not a valid MAC address (too long)")
        return mac


class SyncMacLookup(BaseMacLookup):
    def __init__(self: SyncMacLookup) -> NoReturn:
        self.prefixes = None

    def update_vendors(self: SyncMacLookup, url: Text = OUI_URL) -> NoReturn:
        logger.debug("Downloading MAC vendor list")
        session: requests.sessions.Session
        response: requests.models.Response = requests.get(url)
        f: _io.BufferedWriter
        with open(str(SyncMacLookup.cache_path), mode='wb') as f:
            li: Text
            for li in response.text.split('\n'):
                line = li.encode()  # conversion a bytes
                if b"(base 16)" in line:
                    prefix: bytes
                    vendor: bytes
                    prefix, vendor = (i.strip() for i in line.split(b"(base 16)", 1))
                    self.prefixes[prefix] = vendor
                    f.write(prefix + b":" + vendor + b"\n")

    def load_vendors(self: SyncMacLookup) -> NoReturn:
        self.prefixes: Dict[bytes, bytes] = dict()

        if not SyncMacLookup.cache_path.exists():
            Path(SyncMacLookup.cache_path.parent).mkdir(parents=True, exist_ok=True)
            self.update_vendors()
        else:
            logger.debug("Loading vendor list from cache")
            with open(str(SyncMacLookup.cache_path), mode='rb') as f:
                # Loading the entire file into memory, then splitting is
                # actually faster than streaming each line. (> 1000x)
                for li in (f.read()).splitlines():
                    prefix, vendor = li.split(b":", 1)
                    self.prefixes[prefix] = vendor
        logger.debug(f"Vendor list successfully loaded: {len(self.prefixes)} entries")

    def lookup(self: SyncMacLookup, mac: Text) -> Text:
        mac: AnyStr = self.sanitise(mac)
        if not self.prefixes:
            self.load_vendors()
        if type(mac) == str:
            mac = mac.encode("utf8")
        return self.prefixes[mac[:6]].decode("utf8")


class MacLookup(BaseMacLookup):
    def __init__(self: MacLookup) -> NoReturn:
        self.sync_lookup: SyncMacLookup = SyncMacLookup()

    def update_vendors(self: MacLookup, url: Text = OUI_URL) -> NoReturn:
        return self.sync_lookup.update_vendors(url)

    def lookup(self: MacLookup, mac: Text) -> NoReturn:
        return self.sync_lookup.lookup(mac)

    def load_vendors(self: MacLookup) -> NoReturn:
        return self.sync_lookup.load_vendors()


def main() -> NoReturn:
    if len(sys.argv) < 2:
        logger.info(f"Usage: {sys.argv[0]} [MAC-Address]")
        sys.exit(0)
    try:
        logger.info(SyncMacLookup().lookup(sys.argv[1]))
    except KeyError:
        logger.error("Prefix is not registered")
    except InvalidMacError as e:
        logger.error("Invalid MAC address:", e)


if __name__ == "__main__":
    main()
