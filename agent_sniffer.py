import requests
import socket
from scapy3k.all import *
import subprocess
import re

#------------------ global variables ----------------------
SERVER_PORT = 8200
MY_IP = socket.getaddrinfo('','')[-1][-1][0]
IP_API = '185.136.177.189'
URL = 'http://ip-api.com/line'
list_to_send = [0]
counter = 0
ip_to_country = {}
ip_to_prog = {}

def check(pack):
    '''
    the function check if the pack is valid
    :param pack: packet from sniff
    :return: True / False
    '''
    return IP in pack and (UDP in pack or TCP in pack)

def geo_ip(ip):
    '''
    the function get the contry of the ip
    :param ip: ip [str]
    :return: contry [str]
    '''
    html = (requests.get(URL+'/'+ip)).text
    num = html.find('\n') + 1
    return html[num:html.find('\n',num)]

def netstat():
    '''
    the function make netstat -nb and get progs
    :return: none
    '''
    global ip_to_prog
    j = 0
    ip = "[0-9.]+.[0-9.]+.[0-9.]+.[0-9.]"
    prog = "[A-Za-z.]+.exe"
    #do netstat
    output = subprocess.Popen(['netstat','-nb'],stdout=subprocess.PIPE).communicate()[0].decode()

    #get ip and progs
    ip_match = re.findall(ip,output)
    prog_match = re.findall(prog,output)
    #get all the out ip
    for i in ip_match:
        if not('127.0.0.1' in i) and not(MY_IP in i):
            ip_to_prog[i[:i.find(':')]] = ''
    keys = ip_to_prog.keys()
    #get progs
    for i in prog_match:
        if not('IntelTechnologyAccessService' in i) and not('LegacyCsLoaderService' in i):
            key = list(keys)[j]
            ip_to_prog[key] = i
            j += 1
            if j == len(list(keys)):
                break
    print(ip_to_prog)


def add_packet(pack):
    '''
    the function edit all data packets
    :param pack: pack from sniff
    :return: none
    '''
    global counter
    global list_to_send
    global ip_to_country
    global ip_to_prog
    list_to_send += ['']
    list_to_send[counter] = {}
    list_to_send[counter]['ip'] = pack[IP].dst
    #get contry
    if pack[IP].dst in ip_to_country:
        print('get old ip. the counter is: ',counter)
        list_to_send[counter]['contry'] = ip_to_country[pack[IP].dst]
    else:
        print('get new ip. the counter is: ',counter)
        list_to_send[counter]['contry'] = geo_ip(pack[IP].dst)
        ip_to_country[pack[IP].dst] = list_to_send[counter]['contry']
    #input?
    list_to_send[counter]['input'] = pack[IP].src == MY_IP
    #get port
    if UDP in pack:
        list_to_send[counter]['port'] = pack[UDP].dport
    else:
        list_to_send[counter]['port'] = pack[TCP].dport
    #get size
    list_to_send[counter]['size'] = len(pack)
    #get prog
    if list_to_send[counter]['ip'] in ip_to_prog:
        list_to_send[counter]['prog'] = ip_to_prog[list_to_send[counter]['ip']]
    elif list_to_send[counter]['contry'] != 'private range' and list_to_send[counter]['contry'] != 'reserved range':
        list_to_send[counter]['prog'] = 'unknown'
    else:
        list_to_send[counter]['prog'] = 'NONE'
    print('and the packet is: ',list_to_send[counter])
    counter += 1
    if counter >= 7:
        send()
        counter = 0
        netstat()


def send():
    global  list_to_send
    # Create a non-specific UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Sending a message to server
    server_address = ("127.0.0.1", SERVER_PORT)
    sock.connect(server_address)
    sock.sendto(str(list_to_send).encode(),server_address)

    # Closing the socket
    sock.close()
    list_to_send = ['']

def main():
    print('my ip is: ',MY_IP)
    packs = sniff(lfilter=check,prn=add_packet)
    send()


if __name__ == '__main__':
    main()
