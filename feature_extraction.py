#!/usr/bin/python

# --------------------------------------------------------------
#   Network Packet Sniffer:
#       a packet preprocessor that reads raw PCAP packet data,
#           aggregates packets into connection records, and
#           extracts/derives various features of the connections
#           consistent with those of the KDD CUP 99 dataset.
#
# --------------------------------------------------------------


#Steps
# 1.Create connection dictionary from pcap file......
# 2. Scraping basic data on transmission(TCP/UDP) and address protocols(IP)

import pyshark
import time
from sys import argv
import sys

records=[['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'index', 'idx',
                  'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                  'dst_bytes', 'land', 'wrong_fragment', 'urgent','hot', 'num_failed_logins', 'logged_in', 'lnum_compromised', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_access_files', 'num_outbound_cmds', 'is_hot_login',
            'is_guest_login','count', 'srv_count', 'same_srv_rate', 'diff_srv_rate', 'long_same_src_port_rate',  'srv_long_diff_host_rate', 'serror_rate', 'srv_serror_rate', 'long_rerror_rate', 'srv_long_rerror_rate']]
# input: Packet capture file
# output: full dictionary of Connection ID to all packets written into csv
def create_connection_records(cap):
    
    ## Collect packets from the same connection, create connection dict
    
    raw_connections = {}
    # udp_count = 0
    icmp_count = 0
    start_time = time.time()

    for packet in cap:      
        try:
            if 'tcp' in packet:				
                key = "tcp_conn" + packet.tcp.stream   #data at tcp protocol
            elif 'udp' in packet:                      #stream tracks count of packet 
                key = 'udp_conn' + packet.udp.stream   #in a protocol
         
            elif 'icmp' in packet:
                key = "icmp_conn" + str(icmp_count)
                icmp_count += 1
            else:								# not record packets that aren't TCP/UDP/ICMP                
                continue

            									# If the packet not in a connection record, make a new one!
            if key not in raw_connections.keys():
                raw_connections[key] = [packet]
            else:
                lst = raw_connections[key]
                lst.append(packet)
        except AttributeError:
            continue
    print("--- %s seconds to collect connection records ---" % (time.time() - start_time))
    print('Connections found: ' + str(len(raw_connections)))
    return raw_connections


def ip_address_index(ip_address, ipv4=True):
    power = 0
    index = 0
    if ipv4:
        numeric_parts = ip_address.split('.')
        numeric_parts.reverse()
        for num in numeric_parts:
            index += int(num) * pow(10, power)
            power += 3
    else:
        print(ip_address)
        index = 1
    return index


def initialize_connection(raw_connections):
    connections = []
    				# Get the service name
    service_mapping = get_iana()
    				# Know the index number so you can get the list index 
    idx = 0

    for key, packet_list in raw_connections.items():
        src_bytes = 0
        dst_bytes = 0
        wrong_frag = 0
        urgent = 0

        idx += 1
        if 'tcp' in packet_list[0]:
            protocol = 'tcp'
            duration = float(packet_list[-1].tcp.time_relative)
            src_port = int(packet_list[0].tcp.srcport)
            dst_port = int(packet_list[0].tcp.dstport)
            if src_port <= dst_port:
                if ('tcp', src_port) not in service_mapping.keys():
                    service="Unassigned"
                else:
                    service = service_mapping[('tcp', src_port)]
            else:
                if ('tcp', dst_port) not in service_mapping.keys():
                    service="Unassigned"
                else:
                    service = service_mapping[('tcp', dst_port)]
              							  #service = service_mapping[('tcp', dst_port)]

        elif 'udp' in packet_list[0]:
            protocol = 'udp'
            duration = float(packet_list[-1].udp.time_relative)
            src_port = int(packet_list[0].udp.srcport)
            dst_port = int(packet_list[0].udp.dstport)
            if src_port <= dst_port:
                if ('udp', src_port) not in service_mapping.keys():
                    service="Unassigned"
                else:
                    service = service_mapping[('udp', src_port)]
            else:
                if ('udp', dst_port) not in service_mapping.keys():
                    service="Unassigned"
                else:
                    service = service_mapping[('udp', dst_port)]
        elif 'icmp' in packet_list[0]:
            protocol = 'icmp'
            src_port = int(packet_list[0].icmp.srcport)
            dst_port = int(packet_list[0].icmp.dstport)
            duration = float(packet_list[0].icmp.time_relative)
           
            service = 'eco_i'
        else:
            continue

        duration = int(duration)


        if 'ip' in packet_list[0]:
            # IPv4
            src_ip = packet_list[0].ip.src
            dst_ip = packet_list[0].ip.dst
            index = ip_address_index(dst_ip)
            status_flag = get_connection_status(packet_list)
        else:
            # IPv6
            src_ip = packet_list[0].ipv6.src
            dst_ip = packet_list[0].ipv6.dst
            index = ip_address_index(dst_ip, False)
            status_flag = get_connection_status(packet_list, False)

  	#for loopback connection
        if src_ip == dst_ip and src_port == dst_port:
            land = 1
        else:
            land = 0

        timestamp = packet_list[-1].sniff_timestamp
        # traverse packets (some basic features are aggregated from each packet in whole connection)
        for packet in packet_list:
            if 'ip' in packet_list[0]:
                if src_ip == packet.ip.src:
                    src_bytes += int(packet.length.size)
                else:
                    dst_bytes += int(packet.length.size)
            else:
                if src_ip == packet.ipv6.src:
                    src_bytes += int(packet.length.size)
                else:
                    dst_bytes += int(packet.length.size)

            # Urgent packets only happen with TCP
            if protocol == 'tcp':
                if packet.tcp.flags_urg == '1':
                    urgent += 1
                if packet.tcp.checksum_status != '2':
                    wrong_frag += 1

            elif protocol == 'udp':
                if packet.udp.checksum_status != '2':
                    wrong_frag += 1

            elif protocol == 'icmp':
                if packet.icmp.checksum_status != '2':
                    wrong_frag += 1

     #writing into record file
        record = [timestamp, src_ip, src_port, dst_ip, dst_port, index, idx,
                  duration, protocol, service, status_flag, src_bytes,
                  dst_bytes, land, wrong_frag, urgent]
        '''col = ['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'index', 'idx',
                  'duration', 'protocol', 'service', 'status_flag', 'src_bytes',
                  'dst_bytes', 'land', 'wrong_frag', 'urgent']'''
        connections.append(record)
        bul=0;
        temp=(get_content_data(packet_list))
        for rec in temp:
            record.append(rec)
        '''if bul==0:
            records.append(col)
            bul=1'''
        records.append(record)

        print(record)
       

    # sort in terms of time....
    print("records are \n")
    print(records)
    return sorted(connections, key=lambda x: x[0])


def get_connection_status(packets, ipv4=True):

    if 'udp' in packets[0] or 'icmp' in packets[0]:
        return 'SF'
     	 #ACK - sudo tcpdump 'tcp[13] & 16 != 0'
	 #  SYN - sudo tcpdump 'tcp[13] & 2 != 0'
	 # FIN - sudo tcpdump 'tcp[13] & 1 != 0'
    	 # URG - sudo tcpdump 'tcp[13] & 32 != 0'
   	 # PSH - sudo tcpdump 'tcp[13] & 8 != 0'
     	# RST - sudo tcpdump 'tcp[13] & 4 != 0'''

    # NO S2F or S3F was found
    conn = {'INIT': {('0', '1', '1', '0', '0'): 'S4', ('1', '0', '0', '0', '1'): 'SH', ('1', '1', '0', '0', '0'): 'S0'}, # OTH IS ACCOUNTED FOR
            'S4': {('0', '0', '0', '1', '0'): 'SHR', ('0', '0', '0', '0', '1'): 'RSTRH'},
            'SH': {},              
            'SHR': {},              
            'RSTRH': {},          
            'OTH': {},              
            'S0': {('0', '1', '1', '0', '0'): 'S1', ('0', '0', '0', '1', '0'): 'REJ', ('1', '0', '0', '1', '0'): 'RST0S0'},
            'REJ': {},             
            'RST0S0': {},           
            'RST0': {},             
            'RSTR': {},       
            'S1': {('1', '0', '1', '0', '0'): 'ESTAB', ('1', '0', '0', '1', '0'): 'RST0', ('0', '0', '0', '1', '0'): 'RSTR'},
            'ESTAB': {('1', '0', '1', '0', '1'): 'S2', ('0', '0', '1', '0', '1'): 'S3'},
            'S2': {('0', '0', '1', '0', '0'): 'SF'},
            'S3': {('1', '0', '1', '0', '0'): 'SF'},
            'SF': {}}                 
    # Define source and destination
    if ipv4:
        source_ip = packets[0].ip.src
    else:
        source_ip = packets[0].ipv6.src
    connection_status = 'INIT'


  

    for packet in packets:
        if ipv4:
            if source_ip == packet.ip.src:
                key = ('1', packet.tcp.flags_syn, packet.tcp.flags_ack, packet.tcp.flags_reset, packet.tcp.flags_fin)
            else:
                key = ('0', packet.tcp.flags_syn, packet.tcp.flags_ack, packet.tcp.flags_reset, packet.tcp.flags_fin)
        else:
            if source_ip == packet.ipv6.src:
                key = ('1', packet.tcp.flags_syn, packet.tcp.flags_ack, packet.tcp.flags_reset, packet.tcp.flags_fin)
            else:
                key = ('0', packet.tcp.flags_syn, packet.tcp.flags_ack, packet.tcp.flags_reset, packet.tcp.flags_fin)


        try:
            connection_status = conn[connection_status][key]
        except KeyError:
            if connection_status == 'INIT':
                return 'OTH'
            elif connection_status == 'SH' or connection_status == 'SHR':
                return connection_status
            elif connection_status == 'RSTRH' or connection_status == 'OTH':
                return connection_status
            elif connection_status == 'REJ' or connection_status == 'RST0S0' or connection_status == 'RST0':
                return connection_status
            elif connection_status == 'RSTR' or connection_status == 'SF':
                return connection_status
            else:
                continue
    return connection_status


def get_content_data(packet_list):
    hot = 0
    num_failed_logins = 0
    logged_in = 0
    num_compromised = 0
    root_shell = 0
    su_attempted = 0
    num_root = 0
    num_file_creations = 0
    num_access_files = 0
    num_outbound_cmds = 0
    is_hot_login = 0
    is_guest_login = 0

    packet_no = 1
    for packet in packet_list:
        try:
            # Get the ASCII output
            byte_list = packet.tcp.payload.replace(':', '')
            commmand = bytes.fromhex(byte_list).decode()
         
            print(commmand, end="")

            # First check if for login attempt successful or not
            if logged_in == 1:
                # User is logged in, try to get the prompt!
                if '#' in commmand:
                    root_shell = 1
                if '$' or '#' in commmand:
                    print(commmand, end='')
            else:
                # User is NOT logged in
                if 'Last login' in commmand:
                    logged_in = 1
                if 'failed' in commmand:
                    num_failed_logins += 1
            packet_no += 1
        except UnicodeDecodeError:
            continue
        except AttributeError:
            continue
    return (hot, num_failed_logins, logged_in, num_compromised, logged_in, num_compromised, root_shell,
            su_attempted, num_root, num_file_creations, num_access_files, num_outbound_cmds, is_hot_login,
            is_guest_login)


# Derive time-based traffic features (over 2 sec window by default)...

# ASSUMING IT IS ALREADY SORTED BY TIMESTAMP...
def derive_time_features(connection_idx, connections, time_window=2.0):
    pass



def derive_host_features(current_connection, idx, connections, hosts=256):
    long_services = {}
    srv_long_hosts = {}
    long_count = 0
    long_serror_count = 0
    long_rerror_count = 0
    long_same_services = 0
    long_diff_services = 0
    long_same_src_ports = 0

    srv_long_count = 0
    srv_long_serror_count = 0
    srv_long_rerror_count = 0
    srv_long_diff_hosts = 0






    for i in range(idx, idx + hosts):
        #Catch index out of bound
        try:
            connections[i]
        except IndexError:
            break

        if current_connection[3] == connections[i][3]:
            long_count += 1

            # count various errors
            if current_connection[10] != "SF":
                if 'S' in connections[i][0]:
                    long_serror_count += 1
                elif 'R' in connections[i][0]:
                    long_rerror_count += 1

            # count the  # of same services
            if current_connection[9] == connections[i][9]:
                long_same_services += 1

            # count the # of unique (different) services
            if long_count == 1:
                long_services[long_diff_services] = connections[i][8]
                long_diff_services += 1
            else:
                j = 0
                for j in range(0, long_diff_services, 1):
                    if long_services[j] == connections[i][8]:
                        break
                if j == long_diff_services:
                    long_services[long_diff_services] = connections[i][8]
                    long_diff_services += 1
            # count the  # of same source port
            if current_connection[2] == connections[i][2]:
                long_same_src_ports += 1

        # for the same service
        if current_connection[9] == connections[i][9]:
            srv_long_count += 1
            # count various errors
            if connections[i][10] != "SF":
                if 'S' in connections[i][10]:
                    srv_long_serror_count += 1
                elif 'R' in connections[i][10]:
                    srv_long_rerror_count += 1

            if srv_long_count == 1:
                srv_long_hosts[srv_long_diff_hosts] = connections[i][3]
                srv_long_diff_hosts += 1
            else:
                j = 0
                for j in range(0, srv_long_diff_hosts, 1):
                    if srv_long_hosts[j] == connections[i][3]:
                        break
                if j == srv_long_diff_hosts:
                    srv_long_hosts[srv_long_diff_hosts] = connections[i][3]
                    srv_long_diff_hosts += 1
    # End of for loop
    if long_count > 0:
        long_serror_rate = long_serror_count / long_count
        long_rerror_rate = long_rerror_count / long_count
        if long_diff_services > 1:
            long_diff_srv_rate = long_diff_services / long_count
        else:
            long_diff_srv_rate = 0
        long_same_srv_rate = long_same_services / long_count
        long_same_src_port_rate = long_same_src_ports / long_count

    else:
        long_serror_rate = 0
        long_rerror_rate = 0
        long_diff_srv_rate = 0
        long_same_srv_rate = 0
        long_same_src_port_rate = 0

    if srv_long_count > 0:
        srv_long_serror_rate = srv_long_serror_count / srv_long_count
        srv_long_rerror_rate = srv_long_rerror_count / srv_long_count
        if srv_long_diff_hosts > 1:
            srv_long_diff_host_rate = srv_long_diff_hosts / srv_long_count
        else:
            srv_long_diff_host_rate = 0
    else:
        srv_long_serror_rate = 0
        srv_long_rerror_rate = 0
        srv_long_diff_host_rate = 0

    # Return results
    return long_count, srv_long_count, long_same_srv_rate, long_diff_srv_rate, long_same_src_port_rate,  srv_long_diff_host_rate, long_serror_rate, srv_long_serror_rate, long_rerror_rate, srv_long_rerror_rate


# the main function
def collect_connections(input_file, keep_extra=False):
    # Read in the file

    capture = pyshark.FileCapture(input_file)
    #capture=input_file
    #sys.exit()
    # dictionary mapping of connection number to packets within connection
    raw_connections = create_connection_records(capture)


    # -------------------------------------------------------------------------
    # Derive basic features of each connection, create Connection tuples list: Columns 1 - 11
    # -------------------------------------------------------------------------
    connections = initialize_connection(raw_connections)

    # Derive Time and Host Computations!
    connection_record_counter = 0
    
    for connection_record in connections:
        # ---------------------------------------------------------------------
        # Derive time-based traffic features (over 2 sec window)
        # ---------------------------------------------------------------------
        # Derive host-based traffic features (same host over 100 connections)
        #  ---------------------------------------------------------------------
        
        host_traffic = derive_host_features(connection_record, connection_record_counter, connections,len(connections))
        for rec in host_traffic:
            records[connection_record_counter+1].append(rec)
        print(host_traffic)
 
        connection_record_counter += 1


        print("Completed Connection Record: " + str(connection_record_counter))

    # ---------------------------------------------------------------------
    # Traverse Connection list, generate CSV file
    # ---------------------------------------------------------------------
    
    with open('kdd.csv', 'w+') as out:
     
        for record in connections:
            if keep_extra:
                out.write(','.join(list(record)) + '\n')
            else:
                filtered_line = list(record)[7:]
                filtered_line = ','.join([str(i) for i in filtered_line])
                out.write(filtered_line)
                out.write('\n')


def main():
    
    if len(argv) == 1:
        cap_file = './outside.tcpdump'

        collect_connections(cap_file)
    elif len(argv) == 2:
        cap_file = argv[1]


        collect_connections(cap_file)

        with open('records.csv', 'w+') as out:

            for record in records:
                    filtered_line = list(record)
                    filtered_line = ','.join([str(i) for i in filtered_line])
                    out.write(filtered_line)
                    out.write('\n')


        print('Connection records generated, written to records.csv...')
        
  

    else:
        print('Usage: python3 kdd99_preprocessor.py <pcap-file>')




# Return a dictionary of tcp/udp to port numbers
def get_iana():


    # Open the CSV file
    service_mapping = {}
    filename = './all.csv'
    with open(filename, 'r') as fd:

        for line in fd:
            stuff = line.split(',')
            try:
                service = stuff[0]
                port_protocol_tuple = (stuff[2].lower(), int(stuff[1]))
                if service == '' or stuff[1] == '' or stuff[2] == '':
                    continue
                else:
                    # Ensure the port is number!
                    # print(port_protocol_tuple)
                    # print(service)
                    service_mapping[port_protocol_tuple] = service
            except IndexError:
                continue
            except ValueError:
                continue
    # Manually enter port 80
    service_mapping[('tcp', 80)] = 'http'
    service_mapping[('udp', 80)] = 'http'
    service_mapping[('udp', 50005)] = 'Unassigned'

    return service_mapping


# pass control to collect_connections()
if __name__ == '__main__':
    main()
    exit(0)
exit(0)
    
