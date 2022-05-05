#!/usr/bin/env python3
"""Decipher Xiaomi's MiHome local binary protocol from Wireshark / pcap-ng
captures.

(c) 2017 Wolfgang Frisch
https://github.com/ximihobi

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import sys
import argparse
import json
import pprint
import time
import datetime
import ipaddress
try:
    import pyshark
except ImportError:
    print("ERROR: can't import pyshark. pip3 install pyshark", file=sys.stderr)
    sys.exit(1)
import milo

MAC_PREFIXES_XIAOMI = frozenset([
    "78:11:dc", "00:9E:C8", "0C:1D:AF", "10:2A:B3", "14:F6:5A", "18:59:36",
    "20:82:C0", "28:6C:07", "28:E3:1F", "34:80:B3", "34:CE:00", "38:A4:ED",
    "3C:BD:3E", "58:44:98", "64:09:80", "64:B4:73", "64:CC:2E", "68:DF:DD",
    "74:23:44", "74:51:BA", "78:02:F8", "7C:1D:D9", "8C:BE:BE", "98:FA:E3",
    "9C:99:A0", "A0:86:C6", "AC:C1:EE", "AC:F7:F3", "B0:E2:35", "C4:0B:CB",
     "D4:97:0B", "F0:B4:29", "F4:8B:32", "F8:A4:5F", "FC:64:BA","04:cf:8c"
])


def get_macs(packet):
    """Get the MAC addresses from a PyShark packet.
    Returns (source MAC, destination MAC)
    """
    if "eth" in packet:
        return (packet.eth.src, packet.eth.dst)
    elif "sll" in packet :
        return (packet.sll.src_eth)
    raise Exception("Cannot find a MAC address.")

filename = '12_26write_cz_testdata.txt'
tshark_path = 'G:\\wireshark\\tshark.exe'
capture = pyshark.LiveCapture(interface="3", bpf_filter="host 192.168.137.21 and port 54321",tshark_path=tshark_path,use_json=True, include_raw=True)
collect = {'time':time.time(),'speed':0,'dir':0,'len':0,'command':''}
for packet in capture.sniff_continuously():
    last_time=collect['time']
    now_trans = datetime.datetime.strptime(packet.sniff_timestamp[0:28], "%b %d, %Y %H:%M:%S.%f")
    collect['time'] = now_trans.timestamp()
    if (collect['time']-last_time==0):
        collect['speed']=6666
    else:collect['speed'] = 1/(collect['time']-last_time)
    if (ipaddress.ip_address(packet.ip.src).is_private
            and ipaddress.ip_address(packet.ip.dst).is_private):
        continue
    if (ipaddress.ip_address(packet.ip.src).is_private):
        collect['dir']=1
        last_len1 = collect['len']
    elif ipaddress.ip_address(packet.ip.dst).is_private:
        collect['dir']=0
        last_len0= collect['len']
    collect['len'] = packet.length
    mac_src= get_macs(packet)
    raw_packet=packet.get_raw_packet()
    data = raw_packet[42:]
    mp = milo.MiioPacket()
    mp.read(data)
    decrypted = None
    token = bytearray.fromhex('436D6747555A566B7876753570356937')
    if len(mp.data) == 0:
        collect['command']='Null'
    else:
        decrypted = milo.decrypt(token, data)
        collect['command']=decrypted.decode('UTF-8')
    print("\t"+str(collect['time'])+"\t"+str(collect['speed'])+"\t"+str(collect['dir'])+"\t"+str(collect['len'])+"\t"+collect['command']+"\n")
    with open(filename, 'a+') as f:  # 如果filename不存在会自动创建， 'w'表示写数据，写之前会清空文件中的原有数据！
        f.write("\t"+str(collect['time'])+"\t"+str(collect['speed'])+"\t"+str(collect['dir'])+"\t"+str(collect['len'])+"\t"+collect['command']+"\n")
    # print("\t" + str(collect['time']) + "\t" + str(collect['speed']) + "\t" + str(collect['dir']) + "\t" + str(
    #     collect['len']) +"\n")
    # with open(filename, 'a+') as f:  # 如果filename不存在会自动创建， 'w'表示写数据，写之前会清空文件中的原有数据！
    #     f.write("\t" + str(collect['time']) + "\t" + str(collect['speed']) + "\t" + str(collect['dir']) + "\t" + str(
    #         collect['len']) + "\t" + "\n")


