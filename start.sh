#!/bin/bash


# TODO: Take number of packets/timeout as arg?
#         take interface name as arg?

#pip3 install pyshark
#pip3 install tshark
#pip3 install trollius
#sudo rm -rf recordss.csv

echo "reading raw packet data from the wire"
#sudo tcpdump -c 200 -s0 -i wlp2s0 -w sniff.pcap
sudo tcpdump -c 400 -i wlp2s0 -w sniff.pcap
sudo python3 feature_extraction.py sniff.pcap 
sudo rm -rf sniff.pcap
echo "feeding connection records into ML module"

sudo python3 main.py
# clean up

#sudo rm packets.csv

