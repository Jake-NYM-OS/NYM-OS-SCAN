import socket
import requests
import dns.resolver
import whois
import ipaddress

iiii = [
'███╗░░██╗██╗░░░██╗███╗░░░███╗░░░░░░░█████╗░░██████╗  ████████╗░█████╗░░█████╗░██╗░░░░░',
'████╗░██║╚██╗░██╔╝████╗░████║░░░░░░██╔══██╗██╔════╝  ╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░',
'██╔██╗██║░╚████╔╝░██╔████╔██║█████╗██║░░██║╚█████╗░  ░░░██║░░░██║░░██║██║░░██║██║░░░░░',
'██║╚████║░░╚██╔╝░░██║╚██╔╝██║╚════╝██║░░██║░╚═══██╗  ░░░██║░░░██║░░██║██║░░██║██║░░░░░',
'██║░╚███║░░░██║░░░██║░╚═╝░██║░░░░░░╚█████╔╝██████╔╝  ░░░██║░░░╚█████╔╝╚█████╔╝███████╗',
'╚═╝░░╚══╝░░░╚═╝░░░╚═╝░░░░░╚═╝░░░░░░░╚════╝░╚═════╝░  ░░░╚═╝░░░░╚════╝░░╚════╝░╚══════╝']
for x in iiii:
    print(x)

def my_ip_addresses():
    response = requests.get("https://api64.ipify.org")
    my_pub_ip = response.text
    hostname = socket.gethostname()
    my_grey_ip = socket.gethostbyname(hostname)
    print(f"Ваш публичный IP адрес: {my_pub_ip}\nВаш серый IP адрес: {my_grey_ip}")

def scan_ports(ip_address, ports):
    open_ports = []
    for port in range(ports[0], ports[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result_port_scan = sock.connect_ex((ip_address, port))
        if result_port_scan == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def whois_info(domen):
    resultig = whois.whois(domen)
    print(resultig)

def get_dns_records(domain_name):
        result = f"DNS записи для {domain_name}:\n"
        resolver = dns.resolver.Resolver()
        try:
            a_records = resolver.resolve(domain_name, 'A')
            for record in a_records:
                result += f"\nA запись: {record.address}"
        except Exception as e:
            result += f"\nОшибка при получении A записей: {e}"
        try:
            aaaa_records = resolver.resolve(domain_name, 'AAAA')
            for record in aaaa_records:
                result += f'\nAAAA запись: {record.address}'
        except Exception as e:
            result += f"\nОшибка при получении AAAA записей: {e}"
        try:
            mx_records = resolver.resolve(domain_name, 'MX')
            for record in mx_records:
                result += f"\nMX запись: {record.exchange} (Приоритет: {record.preference})"
        except Exception as e:
            result += f"\nОшибка при получении MX записей: {e}"
        try:
            ns_records = resolver.resolve(domain_name,'NS')
            for record in ns_records:
                result += f"\nNS запись: {record.target}"
        except Exception as e:
            result += f"\nОшибка при получении NS записей: {e}"
        try:
            txt_records = resolver.resolve(domain_name, 'TXT')
            for record in txt_records:
                result += f"\nTXT запись: {record}"
        except Exception as e:
            result += f"\nОшибка при получении TXT записей: {e}"
        try:
            srv_records = resolver.resolve(domain_name, 'SRV')
            for record in srv_records:
                result +=f"\nSRV запись: {record}"
        except Exception as e:
            result += f"\nОшибка при получении SRV записей: {e}"
        return result


def whois_scan(input_domain_name):
    try:
        domain_info = whois.whois(input_domain_name)
        if domain_info.status is None:
            return f"Домен {input_domain_name} свободен"
        else:
            result = f"WHOIS данные для {input_domain_name}: "
        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date
        result += f"\nДата создания: {creation_date}"
        if isinstance(domain_info.updated_date, list):
            updated_date = domain_info.updated_date[0]
        else:
            updated_date = domain_info.updated_date
        result += f"\nДата последнего обновления: {updated_date}"
        if domain_info.registrant == None:
            result += f"\nВладелец: Частное лицо"
        else:
            result += f"\nВладелец: {domain_info.registrant}"
        result += f"\nРегистратор: {domain_info.registrar}"
        if domain_info.org == None:
            result += f"\nОрганизация: Засекречено"
        else:
            result += f"\nОрганизация: {domain_info.org}"
        if domain_info.emails == None:
            result += f"\nEmails: Отсутствуют / Засекречены"
        else:
            result += f"\nE-mail: {domain_info.emails}"
        if domain_info.name_servers == None:
            result +=f"\nNameservers: Отсутствуют / Засекречены"
        else:
            result += f"\nNameservers: {domain_info.name_servers}"
        if domain_info.country == None:
            result += f"\nСтрана: Отсутствует / Засекречена"
        else:
            result += f"\nСтрана: {domain_info.country}"
        return result
    except Exception as e:
        return f"Ошибка при получении WHOIS-данных: {e}"


print("Функционал(Выбери и введи цифру):\n1. Узнать свой IP.\n2. Просканировать открытые порты IP адреса.\n3. DNS-Scanner.\n4. Whois-Scanner.")
number = int(input("Ввод: "))
if number == 1:
    my_ip_addresses()
elif number == 2:
    try:
        ip_address = input("Введите IP: ")
        ipaddress.ip_address(ip_address)
    except ValueError:
        print("Введён некорректный IP адрес")
        exit()
    start_port = int(input("Введите начальный порт: "))
    end_port = int(input("Введите конечный порт: "))
    ports = (start_port, end_port)
    open_ports = scan_ports(ip_address, ports)
    if len(open_ports) > 0:
        print("Открытые порты: ")
        for i in open_ports:
            print(f"Порт {i} открыт")
    else:
        print("Открытых портов нет")

elif number == 3:
    domain_name = input("Введите доменное имя: ")
    dns_record = get_dns_records(domain_name)
    print(dns_record)

elif number == 4:
    domain_name = input("Введите доменное имя: ")
    get_whois = whois_scan(domain_name)
    print(get_whois)
else:
    print('Ошибка: Вы не ввели цифру, либо ввели, но не ту.')
