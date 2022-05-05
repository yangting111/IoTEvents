#!/usr/bin/env python3

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

filename = '12_19write_sx_data.txt'
tshark_path = 'G:\\wireshark\\tshark.exe'
capture = pyshark.LiveCapture(interface="3", bpf_filter="host 192.168.137.36",tshark_path=tshark_path,use_json=True, include_raw=True)
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
    # mac_src= get_macs(packet)
    # raw_packet=packet.get_raw_packet()
    # data = raw_packet[42:]
    # mp = milo.MiioPacket()
    # mp.read(data)
    # decrypted = None
    # token = bytearray.fromhex('436D6747555A566B7876753570356937')
    # if len(mp.data) == 0:
    #     collect['command']='Null'
    # else:
    #     decrypted = milo.decrypt(token, data)
    #     collect['command']=decrypted.decode('UTF-8')
    # print("\t"+str(collect['time'])+"\t"+str(collect['speed'])+"\t"+str(collect['dir'])+"\t"+str(collect['len'])+"\t"+collect['command']+"\n")
    # with open(filename, 'a+') as f:  # 如果filename不存在会自动创建， 'w'表示写数据，写之前会清空文件中的原有数据！
    #     f.write("\t"+str(collect['time'])+"\t"+str(collect['speed'])+"\t"+str(collect['dir'])+"\t"+str(collect['len'])+"\t"+collect['command']+"\n")
    print("\t" + str(collect['time']) + "\t" + str(collect['speed']) + "\t" + str(collect['dir']) + "\t" + str(
        collect['len']) +"\n")
    with open(filename, 'a+') as f:  # 如果filename不存在会自动创建， 'w'表示写数据，写之前会清空文件中的原有数据！
        f.write("\t" + str(collect['time']) + "\t" + str(collect['speed']) + "\t" + str(collect['dir']) + "\t" + str(
            collect['len']) + "\t" + "\n")


