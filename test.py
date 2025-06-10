import sys
import uuid

sys.path.append("./xray_url_decoder/")
sys.path.append("./clash_meta_url_decoder/")
sys.path.append("./xray_ping/")

from xray_url_decoder.XrayUrlDecoder import XrayUrlDecoder
from xray_ping.XrayPing import XrayPing

url = "vless://5e332a8b-cbb4-4575-9f05-6fe85a82ccf9@172.66.213.38:443?encryption=none&security=tls&sni=saderatbank-mizanir-mc.tehranazhdar.ir&alpn=h2&fp=chrome&type=httpupgrade&host=saderatbank-mizanir-mc.tehranazhdar.ir&path=%2Flb5LLhHe1M9Ylps0FIsylpT#MCI%20%F0%9F%9A%80"

configs = []
cusTag = uuid.uuid4().hex
c = XrayUrlDecoder(url, cusTag)
c_json = c.generate_json_str()
if c.isSupported and c.isValid:
    configs.append(c_json)
delays = XrayPing(configs, 200)

