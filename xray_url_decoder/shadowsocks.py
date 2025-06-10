import re
from random import randint
from typing import List

from xray_url_decoder.XraySetting import StreamSettings, Mux



class ServerShadowsocks:
    address: str
    port: int
    method: str
    ota: bool
    password: str
    level: int
    def __init__(self, address, port, method, password, ota = False, level = 1) -> None:
        self.address = address
        self.port = port
        self.method = method
        self.password = password
        self.ota = ota
        self.level = level


class SettingsShadowsocks:
    server: List[ServerShadowsocks]

    def __init__(self, servers: List[ServerShadowsocks]) -> None:
        self.servers = servers


class Shadowsocks:
    tag: str
    protocol: str
    settings: SettingsShadowsocks
    streamSettings: StreamSettings
    mux: Mux

    def __init__(self, name: str, settings: SettingsShadowsocks, stream_settings: StreamSettings, mux: Mux) -> None:
        self.tag = name # "proxy_" + str(randint(1111, 9999999)) + "_" + re.sub(r'([/:+])+', '', name[:120])
        self.protocol = "shadowsocks"
        self.settings = settings
        self.streamSettings = stream_settings
        self.mux = mux
