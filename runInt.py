from scapy.all import *
import scapy_ssl_tls.ssl_tls as tls
from datetime import datetime

import socket
import random
import time
import sys

########### Necessary to run before running script ############
#### iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP ####
##### Ensures kernel doesn't send RST for our connections #####

def run_int_sni_probe(sni, tls_packet, dst_ip, max_ttl, interface, dir_path):

    log_file = open("%s/%s_%s" % (dir_path, dst_ip, sni), 'w')

    probe_ttl = 0
    found_count = 0
    while found_count < 2:

        probe_ttl += 1
        curr_ttl = probe_ttl

        print "\n\n=====================> Trying SNI = ", sni, "DST IP = ", dst_ip, "TTL = ", probe_ttl, "found count =", found_count, "\n\n"

        sport = random.randint(1024, 65535)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((interface, 0))

        ################## Establish TCP connection ##################
        seq = random.randint(12345, 67890)

        IP_PACKET = IP(dst = dst_ip)

        SYN = TCP(sport = sport, dport = dport, flags = "S", seq = seq)
        SYNACK = sr1(IP_PACKET / SYN)
        ACK = TCP(sport = sport, dport = dport, flags = "A", seq = seq + 1, ack = SYNACK.seq + 1)

        send(IP_PACKET / ACK)
        ################### Connection established ###################

        # Set TTL in IP header
        IP_PACKET.ttl = probe_ttl
        del IP_PACKET.chksum # WIll force scapy to recalculate checksum after ttl update

        resp, _ = sr(IP_PACKET / ACK / tls_packet, timeout = 2, retry = 0, multi = True)

        expected_packet_found = False
        tls_or_rst_found = False

        for _, ans_packet in resp:
            if ans_packet.haslayer("SSL"):
                try:
                    ans_packet[tls.TLS][tls.TLSAlert]
                    level = ans_packet[tls.TLS][tls.TLSAlert].level
                    description = ans_packet[tls.TLS][tls.TLSAlert].description
                    log_file.write("===========> TLS Alert found at hop %d : level: %d description: %d\n" % (probe_ttl, level, description))
                    log_file.flush()
                    expected_packet_found = True
                    tls_or_rst_found = True

                except Exception as e:
                    pass

                try:
                    ans_packet[tls.TLS][tls.TLSHandshakes][tls.TLSServerHello]
                    log_file.write("===========> TLS Server Hello found at hop %d\n" % probe_ttl)
                    log_file.flush()
                    expected_packet_found = True
                    tls_or_rst_found = True

                except:
                    pass

            elif ans_packet.haslayer("TCP"):
                if ((ans_packet[TCP].flags >> 2) % 2) == 1:
                    log_file.write("===========> RST recevied at hop %d from IP %s\n" % (probe_ttl, ans_packet[IP].src))
                    log_file.flush()
                    expected_packet_found = True
                    tls_or_rst_found = True

                if (ans_packet[TCP].flags % 2) == 1:
                    log_file.write("===========> FIN recevied at hop %d from IP %s\n" % (probe_ttl, ans_packet[IP].src))
                    log_file.flush()
                    expected_packet_found = True
                    tls_or_rst_found = True


            elif ans_packet.haslayer("ICMP"):
                if ans_packet[ICMP].type == 11:
                    log_file.write("===========> ICMP TTL exceeded at hop %d from IP %s\n" % (probe_ttl, ans_packet[IP].src))
                    log_file.flush()
                    expected_packet_found = True

        if not expected_packet_found:
            log_file.write("===========> No ICMP-TTLExceeded/TCP-RST/TLS-ServerHello/TLS-Alert at hop %d\n" % probe_ttl)
            log_file.flush()

        if tls_or_rst_found:
            found_count += 1

        s.close()
        log_file.write("\n\n")
        log_file.flush()
    log_file.close()

    return found_count

if name == "__main__":

    if len(sys.argv) < 6:
        print("Usage: python " + sys.argv[0] + "<correct_sni> <safe_sni> <resolved_ip> <log_dir>")
        sys.exit()
    
    correct_sni, safe_sni, dst_ip, dir_path = sys.argv[1 : 5]

    dport = 443
    max_ttl = 32
    interface = "wlan0"

    # Run INT probe for safe SNI
    with open("tls_client_hello/%s" % (safe_sni), 'rb') as fp:
        safe_sni_client_hello = fp.read()
    required_ttl = run_int_sni_probe(safe_sni, safe_sni_client_hello, dst_ip, max_ttl, interface, dir_path)


    # Run INT probe for correct SNI
    with open("tls_client_hello/%s" % (correct_sni), 'rb') as fp:
        correct_sni_client_hello = fp.read()
    run_int_sni_probe(correct_sni, correct_sni_client_hello, dst_ip, required_ttl - 1, interface, dir_path)
