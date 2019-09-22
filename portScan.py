from socket import socket, SOCK_STREAM, AF_INET
import argparse as ap
from threading import Thread
import re
import progressbar as pb

def scanner(ip, ports, open):
    global results
    global count
    global bar
    results[ip] = {}

    if re.fullmatch('(\d{1,3}\.){3}\d{1,3}', ip) is None:
        results[ip]['error'] = 'Invalid IP address!'
        return False

    for idx, port in enumerate(ports):
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((ip,port))
            results[ip][port] = 'open'
        except:
            results[ip][port] = 'closed/filtered'
        count +=1
        bar.update(count)

def handlePorts(string):
    try:
        if ',' in string:
            return map(lambda x: int(x), string.split(','))
        elif '-' in string:
            firstPort, lastPort = string.split('-')
            return range(int(firstPort), int(lastPort)+1)
        else:
            return [int(string)]
    except:
        raise Exception('Incorrect port format!')

if __name__ == '__main__':
    parser = ap.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', help='One single IP address to scan.')
    group.add_argument('-f', '--file', help='A file containing multiple IPs to scan.')
    parser.add_argument('-p', '--ports', help='One or more ports to scan. Formats accepted: p1... or p1,p2,p3... or p1-pn.', required=True)
    parser.add_argument('-o', '--open', help='Show only open ports.', action='store_true')
    args = parser.parse_args()

    ports = handlePorts(args.ports)
    results = {}
    count = 0

    if args.ip:
        bar = pb.ProgressBar(max_value=len(ports))
        scanner(args.ip, ports, args.open)
    elif args.file:
        try:
            ips = open(args.file,'r').readlines()
            iplist = map(lambda x: x.strip(), ips)
        except Exception as e:
            raise e

        threadsList = []

        bar = pb.ProgressBar(max_value=len(ports)*len(ips))
        for ip in iplist:
            print('Initiating scanner on %s' % ip)
            threadsList.append(Thread(target=scanner, args=((ip, ports, args.open))))

        [t.start() for t in threadsList]
        [t.join() for t in threadsList]

    for ip in sorted(results.keys()):
        print('\nHost %s' % ip)
        for port, state in results[ip].items():
            if port == 'error':
                print('Invalid IP address!')
                continue
            if args.open and state != 'open':
                continue
            print('Port %i is %s!' % (port, state))
