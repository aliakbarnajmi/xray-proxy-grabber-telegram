import ipaddress
import json
import base64
import uuid
from urllib.parse import parse_qs, ParseResult, urlencode, urlparse, urlunparse, unquote
from xray_url_decoder.IsValid import isValid_tls, isValid_reality, isValid_userVless, isValid_vnextVless, isValid_link
from xray_url_decoder.XraySetting import GrpcSettings, TCPSettings, WsSettingsVless, RealitySettings, TLSSettings, Mux, UpgradeSettingsVless, XhttpSettingsVless
from xray_url_decoder.trojan import Trojan, ServerTrojan, SettingsTrojan
from xray_url_decoder.vless import Vless, UserVless, SettingsVless, VnextVless
from xray_url_decoder.vmess import Vmess, UserVmess, VnextVmess, SettingsVmess
from xray_url_decoder.shadowsocks import ServerShadowsocks, SettingsShadowsocks, Shadowsocks
from xray_url_decoder.XraySetting import StreamSettings
from collections import namedtuple


def is_ipv6_address(hostname):
    try:
        ipaddress.IPv6Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

def decode_base64_to_str(b64:str):
    missing_padding = len(b64) % 4
    if missing_padding:
        b64 += '='* (4 - missing_padding)
    return base64.b64decode(b64).decode("utf-8")

def encode_str_to_base64(text:str):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')


def convertVmessLinkToStandardLink(link):
    data: dict = json.loads(base64.b64decode(link[8:]).decode('utf-8'))

    data['type'] = data['net']
    data['path'] = data.get('path', None)
    data['aid'] = data.get('aid', None)
    data['security'] = data.get('tls', None)

    if is_ipv6_address(data["add"]):
        data["add"] = "[{}]".format(data["add"])

    Components = namedtuple(
        typename='Components',
        field_names=['scheme', 'netloc', 'url', 'path', 'query', 'fragment']
    )

    url = urlunparse(
        Components(
            scheme='vmess',
            netloc='{username}@{hostname}:{port}'.format(username=data['id'], hostname=data["add"], port=data["port"]),
            query=urlencode(data),
            path='',
            url='',
            fragment=data['ps']
        )
    )
    return url


class XrayUrlDecoder:
    url: ParseResult
    queries: dict
    link: str
    name: str
    isSupported: bool
    isValid: bool
    type: str
    security: str

    def __init__(self, link, tagUUID=None):
        match link[:5]:
            case "vmess":
                link = convertVmessLinkToStandardLink(link)

        if tagUUID is None:
            tagUUID = uuid.uuid4().hex

        self.link = link
        self.url = urlparse(self.link)
        self.name = tagUUID + "_@_" + (self.url.fragment if len(self.url.fragment) > 0 else "")
        q = parse_qs(self.url.query)
        self.queries = {key: value[0] for key, value in q.items()}
        self.isSupported = True
        self.isValid = True

        self.type = self.getQuery("type")
        self.security = self.getQuery("security")

        check_valid_protocols = ["vless", "vmess", "trojan"]
        if self.url.scheme in check_valid_protocols and not isValid_link(self.url.username, self.url.hostname, self.url.port):
            self.isValid = False

    def setIsValid(self, status: bool):
        if not status:
            self.isValid = status

    def getQuery(self, key) -> str | None:
        try:
            return self.queries[key]
        except KeyError:
            return None

    def generate_json(self) -> Vless | Vmess | Trojan | Shadowsocks | None:
        print(f"SCHEMA: {self.url.scheme}")
        match self.url.scheme:
            case "vless":
                return self.vless_json()
            case "vmess":
                return self.vmess_json()
            case "trojan":
                return self.trojan_json()
            case "ss":
                return self.shadowsocks_json()
            case _:
                self.isSupported = False
                print("schema {} is not supported yet".format(self.url.scheme))

    def generate_json_str(self) -> str:
        json_obj = self.generate_json()
        if json_obj is None:
            return ""
        return json.dumps(json_obj, default=lambda x: x.__dict__, ensure_ascii=False)

    def stream_setting_obj(self) -> StreamSettings | None:
        wsSetting = None
        httpupgradeSettings = None
        grpcSettings = None
        tcpSettings = None
        tlsSettings = None
        realitySettings = None
        xhttpSettings = None

        match self.type:
            case "grpc":
                grpcSettings = GrpcSettings(self.getQuery("serviceName"))
            case "ws":
                headers = {}
                if self.getQuery("sni") is not None:
                    headers["Host"] = self.getQuery("sni")
                if self.getQuery("host"):
                    headers["Host"] = self.getQuery("host")
                wsSetting = WsSettingsVless(self.getQuery("path"), headers)
            case "httpupgrade":
                uhost = ""
                if self.getQuery("sni") is not None:
                    uhost = self.getQuery("sni")
                if self.getQuery("host"):
                    uhost = self.getQuery("host")
                httpupgradeSettings = UpgradeSettingsVless(self.getQuery("path"), uhost)
            case "tcp":
                if self.getQuery("headerType") == "http":
                    header = {
                        "type": "http",
                        "request": {
                            "version": "1.1",
                            "method": "GET",
                            "path": [
                                (self.getQuery("path") if self.getQuery("path") is not None else "/")
                            ],
                            "headers": {
                                "Host": [
                                    self.getQuery("host")
                                ],
                                "User-Agent": [
                                    ""
                                ],
                                "Accept-Encoding": [
                                    "gzip, deflate"
                                ],
                                "Connection": [
                                    "keep-alive"
                                ],
                                "Pragma": "no-cache"
                            }
                        }
                    }

                tcpSettings = TCPSettings(None, header)
            case "xhttp":
                xhost = ""
                if self.getQuery("sni") is not None:
                    xhost = self.getQuery("sni")
                if self.getQuery("host"):
                    xhost = self.getQuery("host")

                xhttpSettings = XhttpSettingsVless(self.getQuery("path"), xhost, self.getQuery("mode"))
            case _:
                self.isSupported = False
                print("type '{}' is not supported yet".format(self.type))
                return

        match self.security:
            case "tls":
                alpn = None
                if self.getQuery("alpn") is not None:
                    alpn = self.getQuery("alpn").split(",")
                allowInsecure = False
                if self.getQuery("allowInsecure") is not None:
                    if str(self.getQuery("allowInsecure")) == "1":
                        allowInsecure = True
                tlsSettings = TLSSettings(self.getQuery("sni"), fingerprint=self.getQuery("fp"), alpn=alpn, allow_insecure = allowInsecure)
                self.setIsValid(isValid_tls(tlsSettings))

            case "reality":
                realitySettings = RealitySettings(self.getQuery("sni"), self.getQuery("pbk"),
                                                  fingerprint=self.getQuery("fp"), spider_x=self.getQuery("spx"),
                                                  short_id=self.getQuery("sid"))
                self.setIsValid(isValid_reality(realitySettings))

            # case _:
            #     self.isSupported = False
            #     print("security '{}' is not supported yet".format(self.security))
            #     return

        streamSetting = StreamSettings(self.type, self.security, wsSetting, httpupgradeSettings, xhttpSettings, grpcSettings,
                                       tcpSettings, tlsSettings, realitySettings)

        return streamSetting

    def vless_json(self) -> Vless:
        user = UserVless(self.url.username, flow=self.getQuery("flow"))
        vnext = VnextVless(self.url.hostname, self.url.port, [user])
        setting = SettingsVless([vnext])
        streamSetting = self.stream_setting_obj()
        mux = Mux()
        vless = Vless(self.name, setting, streamSetting, mux)

        self.setIsValid(isValid_userVless(user) and isValid_vnextVless(vnext))

        return vless

    def vmess_json(self) -> Vmess:
        user = UserVmess(self.url.username, alterId=self.getQuery("aid"), security=self.getQuery("scy"))
        vnext = VnextVmess(self.url.hostname, self.url.port, [user])
        setting = SettingsVmess([vnext])
        streamSetting = self.stream_setting_obj()
        mux = Mux()
        vmess = Vmess(self.name, setting, streamSetting, mux)

        return vmess

    def trojan_json(self) -> Trojan:
        server = ServerTrojan(self.url.hostname, self.url.port, self.url.username)
        setting = SettingsTrojan([server])
        streamSetting = self.stream_setting_obj()
        mux = Mux()
        trojan = Trojan(self.name, setting, streamSetting, mux)

        return trojan

    def shadowsocks_json(self) -> Shadowsocks:
        ss = self.shadowsocks_encoder()
        if not ss:
            return None
        print("*"*50)
        print(ss)
        server = ServerShadowsocks(*ss)
        setting = SettingsShadowsocks([server])
        streamSetting = StreamSettings("tcp")
        mux = Mux()
        shadowsocks = Shadowsocks(self.name, setting, streamSetting, mux)

        return shadowsocks

    def shadowsocks_encoder(self) -> tuple:
        try:
            _body = unquote(self.url.netloc)
            print(f"_body = {_body}")
            _body = _body.strip().replace("`", "").replace("/?POST%20", "").replace("/?outline=1", "")
            if _body.startswith("ey"):
                return None
            errors_string = ["prefix", "security=", "type=", "path=", ","]
            if any(error in _body for error in errors_string):
                return None
            if "@" not in _body:
                _body = decode_base64_to_str(_body)
                if "@" not in _body:
                    return None
            if len(_body.split("@")) == 2:
                _method_pass_b64 = _body.split("@")[0]
                if _method_pass_b64[-2:] == "=":
                    _method_pass_b64 = _method_pass_b64[:-1]
                if _method_pass_b64[-1] == "=":
                    _method_pass_b64 = _method_pass_b64[:-1]
                _method_pass_str = decode_base64_to_str(_method_pass_b64)
                _method_pass_str_parts = _method_pass_str.split(":")
                if len(_method_pass_str_parts) == 2:
                    method = _method_pass_str_parts[0]
                    valid_methods = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305",
                                     "chacha20-ietf-poly1305", "xchacha20-poly1305", "xchacha20-ietf-poly1305", "plain", "none"]
                    if method not in valid_methods:
                        return None
                    password = _method_pass_str_parts[1]
                ip_port = _body.split("@")[1]
                ip = ip_port.split(":")[0]
                port = int(ip_port.split(":")[1])
                skip_ips = ["free.2apzhfa.xyz", "mx2.drawnrisha.one", "free.2weradf.xyz", "120.232.218.106", "120.240.167.113", "console.03.aliyun.aq.kunlunaqs.com", "127.0.0.1"]
                if any(skipIP==ip for skipIP in skip_ips):
                    return None
                return ip, port, method, password
        except Exception as e:
            print(self.url)
            print(e)
            return None


    def is_equal_to_config(self, config_srt: str) -> bool:
        config = json.loads(config_srt)
        if config['protocol'] != self.url.scheme:
            return False

        match self.url.scheme:
            case "vless":
                return (config["settings"]["vnext"][0]["users"][0]["id"] == self.url.username and
                        config["settings"]["vnext"][0]["port"] == self.url.port and
                        config["settings"]["vnext"][0]["address"] == self.url.hostname)
            case "vmess":
                return (config["settings"]["vnext"][0]["users"][0]["id"] == self.url.username and
                        config["settings"]["vnext"][0]["port"] == self.url.port and
                        config["settings"]["vnext"][0]["address"] == self.url.hostname)
            case "trojan":
                return (config["settings"]["servers"][0]["password"] == self.url.username and
                        config["settings"]["servers"][0]["port"] == self.url.port and
                        config["settings"]["servers"][0]["address"] == self.url.hostname)

        return False
