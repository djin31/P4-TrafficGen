from basic_tunnel import *

for i in possible_packets_:
    wrpcap('tests_data.pcap', i/"XXX", append=True)
