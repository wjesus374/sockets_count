#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import psutil
import sys
import time

#For Zabbix Sender
from decimal import Decimal
import inspect
import socket
import struct
import re
import json

# For python 2 and 3 compatibility
try:
    from StringIO import StringIO
    import ConfigParser as configparser
except ImportError:
    from io import StringIO
    import configparser

#Status
AD = "-"
AF_INET6 = getattr(socket, 'AF_INET6', object())
proto_map = {
(AF_INET, SOCK_STREAM): 'tcp',
(AF_INET6, SOCK_STREAM): 'tcp6',
(AF_INET, SOCK_DGRAM): 'udp',
(AF_INET6, SOCK_DGRAM): 'udp6',
}

import logging
import logging.handlers

logger_debug = logging.getLogger('debug')
logger_debug.setLevel(logging.DEBUG)
#fh = logging.FileHandler(errorlog)
#maxBytes=20MBytes
fh = logging.handlers.RotatingFileHandler('/tmp/getsockets.log', maxBytes=20971520, backupCount=5)
formatter = logging.Formatter('%(asctime)s %(name)-8s %(levelname)-8s %(message)s')
fh.setFormatter(formatter)
logger_debug.addHandler(fh)

logger = logger_debug


class ZabbixResponse(object):
    """The :class:`ZabbixResponse` contains the parsed response from Zabbix.
    """
    def __init__(self):
        self._processed = 0
        self._failed = 0
        self._total = 0
        self._time = 0
        self._chunk = 0
        pattern = (r'[Pp]rocessed:? (\d*);? [Ff]ailed:? (\d*);? '
                   r'[Tt]otal:? (\d*);? [Ss]econds spent:? (\d*\.\d*)')
        self._regex = re.compile(pattern)

    def __repr__(self):
        """Represent detailed ZabbixResponse view."""
        result = json.dumps({'processed': self._processed,
                             'failed': self._failed,
                             'total': self._total,
                             'time': str(self._time),
                             'chunk': self._chunk})
        return result

    def parse(self, response):
        """Parse zabbix response."""
        info = response.get('info')
        res = self._regex.search(info)

        self._processed += int(res.group(1))
        self._failed += int(res.group(2))
        self._total += int(res.group(3))
        self._time += Decimal(res.group(4))
        self._chunk += 1

    @property
    def processed(self):
        return self._processed

    @property
    def failed(self):
        return self._failed

    @property
    def total(self):
        return self._total

    @property
    def time(self):
        return self._time

    @property
    def chunk(self):
        return self._chunk


class ZabbixMetric(object):
    def __init__(self, host, key, value, clock=None):
        self.host = str(host)
        self.key = str(key)
        self.value = str(value)
        if clock:
            if isinstance(clock, (float, int)):
                self.clock = int(clock)
            else:
                raise Exception('Clock must be time in unixtime format')

    def __repr__(self):
        """Represent detailed ZabbixMetric view."""

        result = json.dumps(self.__dict__, ensure_ascii=False)
        return result


class ZabbixSender(object):
    def __init__(self,
                 zabbix_server='127.0.0.1',
                 zabbix_port=10051,
                 use_config=None,
                 chunk_size=250,
                 socket_wrapper=None,
                 timeout=10):

        self.chunk_size = chunk_size
        self.timeout = timeout

        self.socket_wrapper = socket_wrapper
        if use_config:
            self.zabbix_uri = self._load_from_config(use_config)
        else:
            self.zabbix_uri = [(zabbix_server, zabbix_port)]

    def __repr__(self):
        """Represent detailed ZabbixSender view."""

        result = json.dumps(self.__dict__, ensure_ascii=False)
        return result

    def _receive(self, sock, count):
        buf = b''

        while len(buf) < count:
            chunk = sock.recv(count - len(buf))
            if not chunk:
                break
            buf += chunk

        return buf

    def _create_messages(self, metrics):
        messages = []

        # Fill the list of messages
        for m in metrics:
            messages.append(str(m))

        return messages

    def _create_request(self, messages):
        msg = ','.join(messages)
        request = '{{"request":"sender data","data":[{msg}]}}'.format(msg=msg)
        request = request.encode("utf-8")
        return request

    def _create_packet(self, request):
        data_len = struct.pack('<Q', len(request))
        packet = b'ZBXD\x01' + data_len + request

        def ord23(x):
            if not isinstance(x, int):
                return ord(x)
            else:
                return x
        return packet

    def _get_response(self, connection):
        response_header = self._receive(connection, 13)

        if (not response_header.startswith(b'ZBXD\x01') or
                len(response_header) != 13):
            result = False
        else:
            response_len = struct.unpack('<Q', response_header[5:])[0]
            response_body = connection.recv(response_len)
            result = json.loads(response_body.decode("utf-8"))
        try:
            connection.close()
        except Exception as err:
            pass

        return result

    def _chunk_send(self, metrics):
        messages = self._create_messages(metrics)
        request = self._create_request(messages)
        packet = self._create_packet(request)

        for host_addr in self.zabbix_uri:

            # create socket object
            connection_ = socket.socket()
            if self.socket_wrapper:
                connection = self.socket_wrapper(connection_)
            else:
                connection = connection_

            connection.settimeout(self.timeout)

            try:
                # server and port must be tuple
                connection.connect(host_addr)
                connection.sendall(packet)
            except socket.timeout:
                connection.close()
                raise socket.timeout
            except Exception as err:
                # In case of error we should close connection, otherwise
                # we will close it after data will be received.
                connection.close()
                raise Exception(err)

            response = self._get_response(connection)

            if response and response.get('response') != 'success':
                raise Exception(response)

        return response

    def send(self, metrics):
        result = ZabbixResponse()
        for m in range(0, len(metrics), self.chunk_size):
            result.parse(self._chunk_send(metrics[m:m + self.chunk_size]))
        return result


def add(c,stat,ref):
    if ref == 1:
        ip, port = c.laddr
    else:
        ip, port = c.raddr


    if re.search(filterports,str(port)):

        #Verificar se a porta local está no dict
        try: stat[str(port)]
        except: stat[str(port)] = None

        if stat[str(port)]:
            total = stat[str(port)]['total'] + 1
            stat[str(port)]['total'] = total
        else:
            stat[str(port)] = []
            stat[str(port)] = {'total':1}

    return stat


def getsockets():
    local = {}
    #remote = {}
    result = {}
    result['local'] = []
    #result['remote'] = []

    for c in psutil.net_connections(kind='inet'):
        #c é igual a: sconn(fd=-1, family=2, type=2, laddr=addr(ip='192.168.122.1', port=53), raddr=(), status='NONE', pid=None)
        #sconn(fd=74, family=2, type=1, laddr=addr(ip='10.55.4.116', port=53102), raddr=addr(ip='40.77.16.143', port=443), status='ESTABLISHED', pid=2612)
        #Filters: Status = ESTABLISHED and PROTO = tcp
        if c.status == 'ESTABLISHED' and c.family == 2 and c.type == 1:
            localdata = add(c,local,1)
            #remotedata = add(c,remote,2)

    result['local'].append(localdata)
    #result['remote'].append(remotedata)
    return result

def writestatistic(configfile,data):
    with open(configfile,"w") as outfile:
        json.dump(data, outfile, ensure_ascii=False, indent=4, sort_keys=True)

def readconf(configfile):
    with open(configfile, "r") as jsonfile:
        data = json.load(jsonfile)

    return data

def writeconf(configfile,data):
    with open(configfile,"w") as outfile:
        json.dump(data, outfile, ensure_ascii=False)

def getconfig(configfile,service):

    with open(configfile, "r") as jsonfile:
        data = json.load(jsonfile)

    for info in data:
        if service in info:
            #print(info[service])
            return info[service]

if __name__ == "__main__":

    while True:
        #Principais configurações
        mainconfig = '/opt/getsocket/sockets_config.json'
        zabbix = getconfig(mainconfig,'zabbix')
        filterdata = getconfig(mainconfig,'filterdata')
        filterports = getconfig(mainconfig,'filterports')

        result = getsockets()
        search = {}

        for key,value in result['local'][0].items():
            search[key] = value['total']

        #Gravar estatistica
        writestatistic('/tmp/sockets_statistic.json',search)

        for zbx in zabbix:

            #Zabbix Server Info
            metrics = []
            m = None

            zabbixserver = zbx['zabbixserver']
            zabbixport = zbx['zabbixport']
            sendtozabbix = zbx['sendtozabbix']

            if sendtozabbix == "yes":
                for info in filterdata:
                    #porta = str(info['porta'])
                    zbxitem = info['zabbix_item']
                    cliente = info['cliente']

                    try: info['multi_porta']
                    except KeyError: info['multi_porta'] = None

                    try:  info['porta']
                    except KeyError:  info['porta'] = None


                    if info['porta']:
                        porta = str(info['porta'])

                        try: send = search[porta]
                        except: send = 0

                        logger.debug("Sender Info: Cliente: [%s] - Item: [%s] - Value: [%s]" %(cliente,zbxitem,send))
                        #print("./zabbix_sender -z %s -p %s -s %s -k %s -o %s" %(zabbixserver,zabbixport,cliente,zbxitem,send))
                        #os.system("./zabbix_sender -z %s -p %s -s %s -k %s -o %s &> /dev/null" %(zabbixserver,zabbixport,cliente,zbxitem,send))
                        m = ZabbixMetric(cliente,zbxitem,send)
                        metrics.append(m)

                    if info['multi_porta']:
                        soma = 0
                        portas = info['multi_porta']


                        for porta in portas:
                            porta = str(porta)
                            try: value = search[porta]
                            except KeyError: value = None

                            if value:
                                soma += value

                        logger.debug("Sender Info: Cliente: [%s] - Item: [%s] - Value: [%s]" %(cliente,zbxitem,soma))
                        #print("./zabbix_sender -z %s -p %s -s %s -k %s -o %s" %(zabbixserver,zabbixport,cliente,zbxitem,soma))
                        m = ZabbixMetric(cliente,zbxitem,soma)
                        metrics.append(m)
                                
                logger.debug('Enviar dados ao Zabbix Server [%s:%s]' %(zabbixserver,zabbixport))
                zbx = ZabbixSender(zabbixserver)
                zbx.send(metrics)

        #Tempo de espera
        time.sleep(60)
