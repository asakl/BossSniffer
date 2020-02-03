import socket
import ast
import time

LISTEN_PORT = 8200
SERVER_PORT = 8808
SERVER_IP = '54.71.128.194'
info_list = []
old_alerts = []

def get_ip_list():
    open_file = open(r"C:\Users\user\Documents\magshimim\net class\s2\c9 boss sniffer\פרוייקט בוס סניפר\settings.dat",'r')
    file_str = open_file.read()
    curr_index = file_str.find('=') + 2
    ip_dict = {}
    flag = 1
    while flag:
        if file_str.find(',',curr_index) < file_str.find('\n'):
            ip_dict[file_str[curr_index:file_str.find(':',curr_index)]] = file_str[file_str.find(':',curr_index) + 1:file_str.find(',',curr_index)]
        else:
            ip_dict[file_str[curr_index:file_str.find(':',curr_index)]] = file_str[file_str.find(':',curr_index) + 1:file_str.find('\n',curr_index)]
        curr_index = file_str.find(',',curr_index) + 1
        if curr_index >= file_str.find('\n'):
            flag = 0
    return ip_dict

def get_blacklist():
    open_file = open(r"C:\Users\user\Documents\magshimim\net class\s2\c9 boss sniffer\פרוייקט בוס סניפר\settings.dat",'r')
    file_str = open_file.read()
    file_str = file_str[file_str.find('=',file_str.find('\n')) + 2:]
    file_list = str(file_str.split(',')).replace('[','{').replace(']','}').split(':')
    file_str = "':'".join(file_list)
    file_dict = ast.literal_eval(file_str)
    return file_dict

def add_to_list(string):
    global info_list
    counter = 0
    flag = 1
    while True:
        if string.find('{',counter) != -1:
            info_list += [ast.literal_eval(string[string.find('{',counter):string.find('}',counter) + 1])]
            counter = string.find('},',counter) + 1
        else:
            break

def edit_html(ip_dict,client_add,income,outcome,ip,ports,contrys,alerts,progs):
    names = []
    for i in ip_dict:
        names.append(i)
    print(names)
    open_file = open(r"C:\Users\user\Documents\magshimim\net class\s2\c9 boss sniffer\פרוייקט בוס סניפר\template\html\template.html",'r')
    file_str = open_file.read()
    file_str = change_time(file_str)
    file_str = change_income(file_str,names,income)
    file_str = change_outcome(file_str,names,outcome)
    file_str = change_ports(file_str,ports)
    file_str = change_ip(file_str,ip)
    file_str = change_contry(file_str,contrys)
    file_str = change_alerts(file_str,alerts)
    file_str = change_prog(file_str,progs)
    new_file = open(r"C:\Users\user\Documents\magshimim\net class\s2\c9 boss sniffer\פרוייקט בוס סניפר\template\html\report.html",'w')
    new_file.write(file_str)
    open_file.close()
    new_file.close()
    return file_str

def change_time(file_str):
    index = file_str.find('Last update:') + 13
    end_index = file_str.find('<',index)
    file_str = file_str.replace(file_str[index:end_index],time.strftime("%d/%m/%Y %H:%M", time.localtime()))
    return file_str

def change_income(file_str,names,income):
    data = []
    for i in income:
        data.append(income[i])
    index = file_str.find('labels') + 8
    end_index = file_str.find(',',index)
    file_str = file_str.replace(file_str[index:end_index],str(names))
    file_str = file_str.replace(file_str[file_str.find('data:',end_index) + 5:file_str.find('}]',end_index)],str(data))
    return file_str

def change_outcome(file_str,names,outcome):
    data = []
    start_change_index = file_str.find('agents-section-outgoing')
    for i in outcome:
        data.append(outcome[i])
    index = file_str.find('labels',start_change_index) + 8
    end_index = file_str.find(',',index)
    file_str = file_str.replace(file_str[index:end_index],str(names))
    file_str = file_str.replace(file_str[file_str.find('data:',end_index) + 5:file_str.find('}]',end_index)],str(data))
    return file_str

def change_ports(file_str,ports):
    lables = []
    data = []
    start_change_index = file_str.find('ports-section-outgoing')
    for i in ports:
        lables.append(i)
    for i in ports:
        data.append(ports[i])
    index = file_str.find('labels',start_change_index) + 8
    end_index = file_str.find(',',index)
    file_str = file_str.replace(file_str[index:end_index],str(lables))
    file_str = file_str.replace(file_str[file_str.find('data:',end_index) + 5:file_str.find('}]',end_index)],str(data))
    return file_str

def change_ip(file_str,ip):
    lables = []
    data = []
    start_change_index = file_str.find('ips-section-outgoing')
    for i in ip:
        lables.append(i)
    for i in ip:
        data.append(ip[i])
    index = file_str.find('labels',start_change_index) + 8
    end_index = file_str.find(',',index)
    file_str = file_str.replace(file_str[index:end_index],str(lables))
    file_str = file_str.replace(file_str[file_str.find('data:',end_index) + 5:file_str.find('}]',end_index)],str(data))
    return file_str

def change_contry(file_str,contrys):
    lables = []
    data = []
    start_change_index = file_str.find('countries-section-incoming')
    for i in contrys:
        lables.append(i)
        data.append(contrys[i])
    index = file_str.find('labels',start_change_index) + 8
    end_index = file_str.find(',',index)
    file_str = file_str.replace(file_str[index:end_index],str(lables))
    file_str = file_str.replace(file_str[file_str.find('data:',end_index) + 5:file_str.find('}]',end_index)],str(data))
    return file_str

def check_alerts(info,name):
    global old_alerts
    alert = []
    blacklist = get_blacklist()
    for i in info:
        if i['ip'] in blacklist and not(i['ip'] in old_alerts):
            temp_tuple = (name,i['ip'])
            alert.append(temp_tuple)
            old_alerts.append(i['ip'])
    return alert

def change_alerts(file_str,alerts):
    index = file_str.find('%%ALERTS%%')
    end_index = file_str.find('\n',index)
    file_str = file_str.replace(file_str[index:end_index],str(alerts))
    return file_str

def change_prog(file_str,progs):
    lables = []
    data = []
    for i in progs:
        if i == '' or i == 'NONE':
            pass
        else:
            lables.append(i)
            data.append(progs[i])
    print(lables,data)
    start_change_index = file_str.find('apps-section-incoming')
    index = file_str.find('labels',start_change_index) + 8
    end_index = file_str.find(',',index)
    file_str = file_str.replace(file_str[index:end_index],str(lables))
    file_str = file_str.replace(file_str[file_str.find('data:',end_index) + 5:file_str.find('}]',end_index)],str(data))
    return file_str

def report_upload(data):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connecting to remote computer 80
    server_address = (SERVER_IP, SERVER_PORT)
    sock.connect(server_address)

    # Sending data to server
    msg = '400#USER=asa.klein'
    sock.sendall(msg.encode())
    # Receiving data from the server
    server_msg = sock.recv(1024)
    server_msg = server_msg.decode()
    print(server_msg)
    data_list = ['700#SIZE=',str(len(data)),',HTML=']

    for i in data:
        data_list += i
        if len(data_list) == 1460:
            msg = ''.join(data_list)
            print(msg)
            sock.sendall(msg.encode())
            data_list = []
    msg = ''.join(data_list)
    sock.sendall(msg.encode())

    msg = '900#BYE'
    sock.sendall(msg.encode())
    server_msg = sock.recv(1024)
    server_msg = server_msg.decode()
    print(server_msg)
    # Closing the socket
    sock.close()

def main():
    counter = 0
    global info_list
    ip_dict = get_ip_list()
    ip_dict['asa'] = '127.0.0.1'
    most_common_ip = {}
    most_common_ports = {}
    most_common_contry = {}
    most_common_progs = {}
    alerts = []

    input_packs_per_agents = {}
    output_packs_per_agents = {}
    for i in ip_dict:
        input_packs_per_agents[i] = 0
        output_packs_per_agents[i] = 0
    print(input_packs_per_agents)
    # Create a non-specific UDP socket
    listening_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Binding to local UDP port 8200
    server_address = ('', LISTEN_PORT)
    listening_sock.bind(server_address)
    while True:
        try:
            # Receiving data from the the socket, could be from anyone!
            client_msg, client_addr = listening_sock.recvfrom(1024)
            print(client_addr)
            print('get msg')
            add_to_list(client_msg.decode())
            print('the msg is:',info_list)
            for i in ip_dict:
                if client_addr[0] == ip_dict[i]:
                    for j in info_list:
                        if j['input'] == False:
                            output_packs_per_agents[i] += j['size']
                        else:
                            input_packs_per_agents[i] += j['size']
                            if not(j['ip'] in most_common_ip):
                                most_common_ip[j['ip']] = j['size']
                            else:
                                most_common_ip[j['ip']] += j['size']
                            if not(j['port'] in most_common_ports):
                                most_common_ports[j['port']] = j['size']
                            else:
                                most_common_ports[j['port']] += j['size']
                            if j['contry'] != 'private range' and j['contry'] != 'reserved range':
                                if not(j['contry'] in most_common_contry):
                                    most_common_contry[j['contry']] = j['size']
                                else:
                                    most_common_contry[j['contry']] += j['size']
                        if 'prog' in j:
                            if not(j['prog'] in most_common_progs):
                                most_common_progs[j['prog']] = j['size']
                            else:
                                most_common_progs[j['prog']] += j['size']
                        alerts += check_alerts(info_list,i)
                    print(input_packs_per_agents,output_packs_per_agents)
            data = edit_html(ip_dict,client_addr,input_packs_per_agents,output_packs_per_agents,most_common_ip,most_common_ports,most_common_contry,alerts,most_common_progs)
            info_list = []
            counter += 1
            if counter == 15:
                report_upload(data)
                counter = 0
                print('finish!')
        except Exception as e:
            print(e)

    # Closing the socket
    listening_sock.close()

if __name__ == '__main__':
    main()
