import sys

sys.path.append("./xray_url_decoder/")
sys.path.append("./clash_meta_url_decoder/")
sys.path.append("./xray_ping/")

from xray_url_decoder.XrayUrlDecoder import XrayUrlDecoder
from xray_ping.XrayPing import XrayPing

url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpvWklvQTY5UTh5aGNRVjhrYTNQYTNB@103.104.247.47:8080#%F0%9F%87%B3%F0%9F%87%B1%20The%20Netherlands"

configs = []
c = XrayUrlDecoder(url)
c_json = c.generate_json_str()
print("-"*50)
print(c_json)

if c.isSupported and c.isValid:
    configs.append(c_json)
delays = XrayPing(configs, 200)

