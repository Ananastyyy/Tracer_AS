import argparse

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from ipwhois import IPWhois
from prettytable import PrettyTable


def tracert(arg):
    table = PrettyTable()
    table.field_names = ["№", "IP", "AS", "Country", "Provider"]
    host_address = arg
    ttl = 1
    while True:
        # Отправляем ICMP Echo Request с заданным TTL
        try:
            pkt = IP(dst=host_address, ttl=ttl) / ICMP()
            reply = sr1(pkt, verbose=False, timeout=1)

            if reply is None:
                # Не удалось получить ответ - хост недоступен или истек таймаут
                break
            else:
                try:
                    obj = IPWhois(reply.src)
                    res = obj.lookup_rdap()
                    table.add_row([ttl, str(reply.src), res.get('asn'),
                                   res.get('asn_country_code'),
                                   res.get('network', {}).get('name')])

                except Exception:
                    table.add_row([ttl, reply.src, "-", "-", "-"])
            if reply.type == 0:
                # получен ICMP Echo Reply
                break
            else:
                # Получен ICMP Time Exceeded
                ttl += 1
        except OSError:
            print("WRONG ADDRESS")
            break
    print(table)


def parsing():
    parser = argparse.ArgumentParser(description='Трассировка автономных систем')
    parser.add_argument(dest='host', help='Адрес или имя хоста')

    return parser.parse_args()


if __name__ == "__main__":
    args = parsing()
    tracert(args.host)
