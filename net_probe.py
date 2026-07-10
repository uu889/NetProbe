#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UU889  网络工具 (桌面版)
================================
零第三方依赖，仅用 Python 标准库 + Tkinter。

功能模块：
  1. 主机存活扫描  —— 扫描一个 IP 段，探测哪些 IP 可以 Ping 通（含时延、TTL）
  2. 端口扫描      —— 对 IP段 / 单个IP / 单个端口 探测 TCP 或 UDP 是否开放
                     （一个模块覆盖需求 2 / 3 / 4）
  3. 路由追踪      —— 追踪到目标 IP 的路由，并对每一跳做地理定位 / 机房归属

仅限对你拥有或已获授权的网络进行测试。
"""

import os
import sys
import re
import csv
import json
import html
import time
import queue
import socket
import tempfile
import platform
import threading
import webbrowser
import subprocess
import ipaddress
import sqlite3
import smtplib
import urllib.request
import concurrent.futures
from datetime import datetime
from email.mime.text import MIMEText
from email.header import Header
import ssl
import getpass
import argparse
import errno
import struct
import random
import statistics
import selectors
import select
import mmap
import gzip
import base64
import secrets
import string
import math
import zlib
import hashlib
import urllib.error
import urllib.parse

# Tkinter 作为可选导入：即便环境无图形库，引擎函数仍可被导入 / 单元测试
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    HAS_TK = True
except Exception:
    HAS_TK = False

SYSTEM = platform.system()          # 'Windows' / 'Darwin' / 'Linux'
IS_WINDOWS = SYSTEM == 'Windows'
IS_MAC = SYSTEM == 'Darwin'
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW，隐藏子进程 cmd 窗口

# ------------------------------------------------------------------ #
#  常量：常用端口与服务名
# ------------------------------------------------------------------ #
COMMON_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    110: 'POP3', 111: 'RPCbind', 123: 'NTP', 135: 'MS-RPC', 137: 'NetBIOS',
    138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap',
    179: 'BGP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    500: 'IKE', 514: 'Syslog', 515: 'LPD', 520: 'RIP', 587: 'SMTP-Sub',
    623: 'IPMI', 631: 'IPP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MSSQL', 1434: 'MSSQL-M',
    1521: 'Oracle', 1701: 'L2TP', 1723: 'PPTP', 1883: 'MQTT', 2049: 'NFS',
    2082: 'cPanel', 2083: 'cPanel-SSL', 2181: 'ZooKeeper', 2375: 'Docker',
    2379: 'etcd', 3306: 'MySQL', 3389: 'RDP', 4369: 'EPMD', 5060: 'SIP',
    5432: 'PostgreSQL', 5601: 'Kibana', 5672: 'AMQP', 5900: 'VNC',
    5985: 'WinRM', 5986: 'WinRM-SSL', 6379: 'Redis', 6443: 'K8s-API',
    7001: 'WebLogic', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt', 9000: 'HTTP-Alt', 9092: 'Kafka', 9200: 'Elasticsearch',
    9300: 'ES-Cluster', 11211: 'Memcached', 15672: 'RabbitMQ-Mgmt',
    27017: 'MongoDB', 50000: 'DB2',
}

# 快速扫描预设端口
TOP_PORTS = [
    21, 22, 23, 25, 53, 67, 69, 80, 110, 111, 123, 135, 137, 139, 143, 161,
    179, 389, 443, 445, 465, 500, 514, 587, 631, 636, 993, 995, 1080, 1194,
    1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375, 3306, 3389, 5060,
    5432, 5601, 5672, 5900, 5985, 6379, 6443, 8000, 8080, 8443, 8888, 9000,
    9092, 9200, 11211, 27017,
]

MAX_HOSTS = 65536      # 单次目标 IP 数量上限
MAX_WORKERS = 500      # 并发上限


# ================================================================== #
#  引擎层：纯函数，不依赖界面
# ================================================================== #
def resolve_host(host):
    """主机名 -> IP；已是 IP 则原样返回；失败返回 None"""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def data_dir():
    """数据/配置目录：Windows=%APPDATA%\\UU889，其它=~/.config/UU889。修复 exe 下找不到文件。"""
    base = os.environ.get('APPDATA') or os.path.join(os.path.expanduser('~'), '.config')
    d = os.path.join(base, 'UU889')
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.getcwd()
    return d


def parse_endpoints(text):
    """解析 host:port 端点批量：支持 IP:端口 / 域名:端口 / [IPv6]:端口，逗号或空格分隔。"""
    eps = []
    for tok in re.split(r'[\s,]+', text.strip()):
        if not tok:
            continue
        m = re.match(r'^\[(.+)\]:(\d+)$', tok)
        if m:
            host, port = m.group(1), int(m.group(2))
        elif tok.count(':') == 1:
            host, _, p = tok.partition(':')
            port = int(p) if p.isdigit() else None
        else:
            host, port = None, None
        if host and port:
            ip = resolve_host(host)
            if ip:
                eps.append((ip, port))
    return eps


# ------------------ 多语言 i18n（内置 en/fr/es/pt + 外部 JSON 语言包） ------------------
LANG = 'zh'
TRANS = {}
_BUILTIN_TRANS = {
    'en': {
        '  主机存活扫描  ': '  Host Discovery  ', '  端口扫描  ': '  Port Scan  ',
        '  路由追踪 + 地理定位  ': '  Traceroute + Geo  ', '  定时监控 + 变更告警  ': '  Monitor + Alerts  ',
        '  网络诊断  ': '  Diagnostics  ', '  链路质量曲线  ': '  Link Quality  ',
        '开始扫描': 'Start Scan', '停止': 'Stop', '清空': 'Clear', '导出结果': 'Export',
        '开始追踪': 'Start Trace', '开始监测': 'Start', '开始监控': 'Start', '停止监控': 'Stop',
        '导出变更': 'Export changes', '设置…': 'Settings…', '导出报表': 'Report', '汇总看板…': 'Dashboard…',
    },
    'fr': {
        '  主机存活扫描  ': "  Découverte d'hôtes  ", '  端口扫描  ': '  Scan de ports  ',
        '  路由追踪 + 地理定位  ': '  Traceroute + Géo  ', '  定时监控 + 变更告警  ': '  Surveillance + Alertes  ',
        '  网络诊断  ': '  Diagnostics  ', '  链路质量曲线  ': '  Qualité du lien  ',
        '开始扫描': 'Scanner', '停止': 'Arrêter', '清空': 'Effacer', '导出结果': 'Exporter',
        '开始追踪': 'Tracer', '开始监测': 'Démarrer', '开始监控': 'Démarrer', '停止监控': 'Arrêter',
        '导出变更': 'Exporter', '设置…': 'Paramètres…', '导出报表': 'Rapport', '汇总看板…': 'Tableau…',
    },
    'es': {
        '  主机存活扫描  ': '  Descubrimiento  ', '  端口扫描  ': '  Escaneo de puertos  ',
        '  路由追踪 + 地理定位  ': '  Traceroute + Geo  ', '  定时监控 + 变更告警  ': '  Monitoreo + Alertas  ',
        '  网络诊断  ': '  Diagnóstico  ', '  链路质量曲线  ': '  Calidad del enlace  ',
        '开始扫描': 'Escanear', '停止': 'Detener', '清空': 'Limpiar', '导出结果': 'Exportar',
        '开始追踪': 'Trazar', '开始监测': 'Iniciar', '开始监控': 'Iniciar', '停止监控': 'Detener',
        '导出变更': 'Exportar', '设置…': 'Ajustes…', '导出报表': 'Informe', '汇总看板…': 'Panel…',
    },
    'pt': {
        '  主机存活扫描  ': '  Descoberta de hosts  ', '  端口扫描  ': '  Varredura de portas  ',
        '  路由追踪 + 地理定位  ': '  Traceroute + Geo  ', '  定时监控 + 变更告警  ': '  Monitor + Alertas  ',
        '  网络诊断  ': '  Diagnóstico  ', '  链路质量曲线  ': '  Qualidade do link  ',
        '开始扫描': 'Escanear', '停止': 'Parar', '清空': 'Limpar', '导出结果': 'Exportar',
        '开始追踪': 'Rastrear', '开始监测': 'Iniciar', '开始监控': 'Iniciar', '停止监控': 'Parar',
        '导出变更': 'Exportar', '设置…': 'Config…', '导出报表': 'Relatório', '汇总看板…': 'Painel…',
    },
}


def available_langs():
    return ['zh'] + sorted(TRANS.keys())


def set_lang(code):
    global LANG
    LANG = code if (code == 'zh' or code in TRANS) else 'zh'


def t(s):
    return TRANS.get(LANG, {}).get(s, s)


def load_langpacks(d):
    """载入内置 + 外部语言包（<数据目录>/lang/*.json，格式 {"language":"de","strings":{"中文":"..."}}）。"""
    global TRANS
    TRANS = {k: dict(v) for k, v in _BUILTIN_TRANS.items()}
    ldir = os.path.join(d, 'lang')
    try:
        for fn in sorted(os.listdir(ldir)):
            if fn.lower().endswith('.json'):
                try:
                    obj = json.load(open(os.path.join(ldir, fn), encoding='utf-8'))
                    code = obj.get('language') or os.path.splitext(fn)[0]
                    TRANS.setdefault(code, {}).update(obj.get('strings', {}))
                except Exception:
                    pass
    except Exception:
        pass


def is_public_ip(ip):
    """是否为公网可定位地址"""
    try:
        o = ipaddress.ip_address(ip)
        return not (o.is_private or o.is_loopback or o.is_link_local or
                    o.is_multicast or o.is_reserved or o.is_unspecified)
    except Exception:
        return False


def expand_targets(text, max_hosts=MAX_HOSTS):
    """
    解析目标表达式为 IP 列表，支持（可用逗号 / 空格分隔多个）：
      - CIDR:            192.168.1.0/24
      - 完整区间:        192.168.1.10-192.168.1.20
      - 末位区间:        192.168.1.10-20
      - 单个 IP:         10.0.0.5
      - 主机名:          example.com
    """
    targets, seen = [], set()

    def add(ip):
        if ip not in seen:
            seen.add(ip)
            targets.append(ip)

    for tok in re.split(r'[\s,]+', text.strip()):
        if not tok:
            continue
        if len(targets) > max_hosts:
            raise ValueError('目标数量超过上限 %d，请缩小范围' % max_hosts)

        if '/' in tok:                                   # CIDR
            net = ipaddress.ip_network(tok, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            for ip in hosts:
                add(str(ip))
        elif '-' in tok:                                 # 区间
            left, right = tok.split('-', 1)
            left, right = left.strip(), right.strip()
            start = ipaddress.ip_address(left)
            if '.' in right:
                end = ipaddress.ip_address(right)
            else:
                base = left.rsplit('.', 1)[0]
                end = ipaddress.ip_address('%s.%s' % (base, right))
            if int(end) < int(start):
                start, end = end, start
            for v in range(int(start), int(end) + 1):
                add(str(ipaddress.ip_address(v)))
                if len(targets) > max_hosts:
                    raise ValueError('目标数量超过上限 %d，请缩小范围' % max_hosts)
        else:                                            # 单 IP / 主机名
            ip = resolve_host(tok)
            if ip is None:
                raise ValueError('无法解析目标: %s' % tok)
            add(ip)

    if not targets:
        raise ValueError('未解析到任何目标')
    return targets


def parse_ports(text):
    """
    解析端口表达式，支持：
      - 单个:   80
      - 列表:   22,80,443
      - 区间:   1-1024
      - 混合:   20-25,80,443,8080
      - 预设:   top / common(常用)  |  all(全部 1-65535)
    """
    t = text.strip().lower()
    if t in ('top', 'common', '常用', 'top100'):
        return list(TOP_PORTS)
    if t in ('all', '全部', '1-65535'):
        return list(range(1, 65536))

    ports = set()
    for tok in re.split(r'[\s,]+', t):
        if not tok:
            continue
        if '-' in tok:
            a, b = tok.split('-', 1)
            a, b = int(a), int(b)
            for p in range(min(a, b), max(a, b) + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(tok)
            if 1 <= p <= 65535:
                ports.add(p)
    if not ports:
        raise ValueError('未解析到任何端口')
    return sorted(ports)


def ping_host(ip, timeout_ms=1000):
    """调用系统 ping 探测单主机存活。返回 {ip, alive, rtt_ms, ttl}"""
    v6 = ':' in ip
    if IS_WINDOWS:
        cmd = ['ping', '-n', '1', '-w', str(int(timeout_ms))] + (['-6'] if v6 else []) + [ip]
    elif IS_MAC:
        cmd = ['ping6', '-c', '1', ip] if v6 else ['ping', '-c', '1', '-W', str(int(timeout_ms)), ip]
    else:  # Linux：-W 单位为秒
        sec = max(1, int(round(timeout_ms / 1000.0)))
        cmd = ['ping', '-c', '1', '-W', str(sec)] + (['-6'] if v6 else []) + [ip]

    result = {'ip': ip, 'alive': False, 'rtt_ms': None, 'ttl': None}
    try:
        total = max(2.0, timeout_ms / 1000.0 + 2.0)
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=total,
                              creationflags=_NO_WINDOW)
        out = (proc.stdout.decode('utf-8', 'ignore') +
               proc.stderr.decode('utf-8', 'ignore'))

        # 不依赖 time/时间 等本地化词，直接匹配 “=<数字>ms”（兼容中文 Windows）
        m = re.search(r'[=<]\s*([\d.]+)\s*ms', out, re.IGNORECASE)
        if m:
            result['rtt_ms'] = float(m.group(1))
        m = re.search(r'ttl[=:]?\s*(\d+)', out, re.IGNORECASE)
        if m:
            result['ttl'] = int(m.group(1))

        if IS_WINDOWS:
            # Windows：真正应答一定带 TTL/时延，据此判断存活（兼容各语言输出）
            result['alive'] = (proc.returncode == 0 and
                               (result['ttl'] is not None or result['rtt_ms'] is not None))
        else:
            result['alive'] = (proc.returncode == 0)
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        result['error'] = str(e)
    return result


def scan_tcp(ip, port, timeout=1.0, grab_banner=False):
    """TCP connect 扫描。state: open / closed / filtered"""
    s = socket.socket(_family_for(ip), socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ''
    try:
        rc = s.connect_ex((ip, port))
        if rc == 0:
            state = 'open'
            if grab_banner:
                try:
                    s.settimeout(0.8)
                    data = s.recv(256)
                    banner = data.decode('utf-8', 'ignore').strip().replace('\r', ' ').replace('\n', ' ')
                except Exception:
                    banner = ''
        else:
            state = 'closed'
    except socket.timeout:
        state = 'filtered'
    except Exception:
        state = 'closed'
    finally:
        try:
            s.close()
        except Exception:
            pass
    return {'ip': ip, 'port': port, 'proto': 'TCP', 'state': state,
            'service': COMMON_PORTS.get(port, ''), 'banner': banner}


# 常见 UDP 服务的“协议探针”：发对应报文，收到合法应答即可**确认开放**。
_UDP_PROBES = {
    53: b'\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01',
    123: b'\x1b' + b'\x00' * 47,
    161: bytes.fromhex('302902010004067075626c6963a01c020400000000020100020100300e300c06082b060102010105000500'),
    137: b'\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01',
    111: b'\x72\xFE\x1D\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA0\x00\x01\x97\x7C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    500: bytes.fromhex('5b5e64c03e99b5110000000000000000011002000000000000000150000001340000000100000001000001280101000803000024010100000080010000058002000280030001800400020000002401020000800100050002000280030001800400020000002401030000800100010002000280030001800400020000002401040000800100050002000280030001800400020500000024010500008001000500020002800300018004000200000000180200000080020002800300038004000280010005'),
    623: b'\x06\x00\xff\x06\x00\x00\x11\xbe\x80\x00\x00\x00',
    1434: b'\x02',
    1900: b'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:1\r\nST:ssdp:all\r\n\r\n',
    5060: (b'OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bKnp\r\n'
           b'From: <sip:nm@nm>;tag=r\r\nTo: <sip:nm@nm>\r\nCall-ID: 1@1\r\n'
           b'CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n'),
    5353: b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',
}


def scan_udp(ip, port, timeout=2.0):
    """
    UDP 扫描（best-effort，无需 root）：对常见端口发协议探针，**仅在收到应答时判定 open**。
      收到应答 -> open ；收到 ICMP 端口不可达 -> closed ；无响应 -> open|filtered（未知，默认不当作开放）
    """
    probe = _UDP_PROBES.get(port, b'\x00')
    state = 'open|filtered'
    try:
        s = socket.socket(_family_for(ip), socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        got = closed = False
        for _ in range(2):
            try:
                s.send(probe)
            except (ConnectionRefusedError, ConnectionResetError, OSError):
                closed = True
                break
            try:
                s.recv(2048)
                got = True
                break
            except socket.timeout:
                pass
            except (ConnectionRefusedError, ConnectionResetError, OSError):
                closed = True
                break
        state = 'open' if got else ('closed' if closed else 'open|filtered')
        s.close()
    except Exception:
        state = 'error'
    return {'ip': ip, 'port': port, 'proto': 'UDP', 'state': state,
            'service': COMMON_PORTS.get(port, ''), 'banner': ''}


def scan_port(ip, port, proto, timeout, grab_banner=False):
    if proto.upper() == 'UDP':
        return scan_udp(ip, port, timeout=max(timeout, 1.5))
    return scan_tcp(ip, port, timeout=timeout, grab_banner=grab_banner)


def geolocate(ip, timeout=5.0, lang='zh-CN'):
    """用 ip-api.com 免费接口查询地理位置 / 运营商 / AS（机房归属线索）。"""
    base = {'ip': ip, 'country': '', 'region': '', 'city': '',
            'isp': '', 'org': '', 'asn': '', 'lat': None, 'lon': None,
            'status': ''}
    if not is_public_ip(ip):
        base['status'] = 'private'
        base['country'] = '内网/保留地址'
        return base
    if _GEO.get('db') and _GEO.get('mode') in ('offline', 'auto'):
        g = geo_offline(ip, _GEO['db'])
        if g:
            return g
        if _GEO.get('mode') == 'offline':
            base['status'] = 'offline-miss'
            base['country'] = '离线库未命中'
            return base
    url = ('http://ip-api.com/json/%s?fields=status,message,country,regionName,'
           'city,isp,org,as,lat,lon,query&lang=%s' % (ip, lang))
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'UU889/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8', 'ignore'))
        if data.get('status') == 'success':
            base.update(status='success', country=data.get('country', ''),
                        region=data.get('regionName', ''), city=data.get('city', ''),
                        isp=data.get('isp', ''), org=data.get('org', ''),
                        asn=data.get('as', ''), lat=data.get('lat'),
                        lon=data.get('lon'))
        else:
            base['status'] = 'fail'
            base['country'] = data.get('message', '查询失败')
    except Exception as e:
        base['status'] = 'error'
        base['country'] = '定位失败(%s)' % e.__class__.__name__
    return base


_HOP_RE = re.compile(r'^\s*(\d+)[:\s]')
_IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


def _parse_hop_line(line):
    """解析一行 traceroute/tracert 输出为 {hop, ip, rtt_ms}；非跳数行返回 None"""
    m = _HOP_RE.match(line)
    if not m:
        return None
    hop = int(m.group(1))
    ipm = _IP_RE.search(line)
    ip = ipm.group(1) if ipm else None
    times = re.findall(r'([\d.]+)\s*ms', line)
    rtt = float(times[0]) if times else None
    return {'hop': hop, 'ip': ip, 'rtt_ms': rtt}


def traceroute_cmd(target, max_hops=30):
    """返回适配当前系统的 traceroute 命令列表（可能含回退）。"""
    v6 = ':' in target
    if IS_WINDOWS:
        return [['tracert', '-d', '-h', str(max_hops)] + (['-6'] if v6 else []) + [target]]
    # Linux / macOS：优先 traceroute，Linux 回退 tracepath
    cmds = [['traceroute'] + (['-6'] if v6 else []) + ['-n', '-m', str(max_hops), target]]
    if not IS_MAC:
        cmds.append(['tracepath', '-n', target])
    return cmds


def run_traceroute(target, max_hops=30, on_hop=None, stop_event=None):
    """
    执行路由追踪，逐跳回调 on_hop(hop_dict)。
    返回所有 hop 列表。命令不存在时抛出 FileNotFoundError。
    """
    hops = []
    last_err = None
    for cmd in traceroute_cmd(target, max_hops):
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, bufsize=1,
                                    universal_newlines=True, creationflags=_NO_WINDOW)
        except FileNotFoundError as e:
            last_err = e
            continue

        try:
            for line in iter(proc.stdout.readline, ''):
                if stop_event is not None and stop_event.is_set():
                    proc.terminate()
                    break
                hop = _parse_hop_line(line)
                if hop:
                    hops.append(hop)
                    if on_hop:
                        on_hop(hop)
            proc.stdout.close()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
        return hops
    raise FileNotFoundError(last_err or 'traceroute/tracert 命令不可用')


def diff_snapshots(prev, cur):
    """比较两次快照集合，返回 (新增, 消失)。用于定时监控的变更检测。"""
    return (cur - prev, prev - cur)


def build_map_html(target, hops):
    """
    由带地理坐标的 hop 列表生成 Leaflet 世界地图 HTML（在线瓦片）。
    hops 为 _trace_worker 收集的原始跳点（含 'geo'）。
    """
    pts = []
    for h in hops:
        g = h.get('geo') or {}
        lat, lon = g.get('lat'), g.get('lon')
        if lat is None or lon is None:
            continue
        loc = ', '.join(x for x in (g.get('city', ''), g.get('region', ''),
                                    g.get('country', '')) if x)
        isp = ' / '.join(x for x in (g.get('isp', ''), g.get('org', ''),
                                     g.get('asn', '')) if x)
        pts.append({'hop': h.get('hop'), 'ip': h.get('ip') or '',
                    'lat': lat, 'lon': lon, 'loc': loc, 'isp': isp,
                    'rtt': ('%.1f' % h['rtt_ms']) if h.get('rtt_ms') is not None else '-'})
    data = json.dumps(pts, ensure_ascii=False)
    tpl = """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>__TITLE__</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<style>html,body{margin:0;height:100%;font-family:sans-serif}#map{height:100%}
#bar{position:absolute;z-index:1000;top:10px;left:52px;background:#fff;padding:6px 10px;
border-radius:6px;box-shadow:0 1px 6px rgba(0,0,0,.3);font-size:13px;max-width:70%}</style>
</head><body>
<div id="bar">路由世界地图 · 目标 <b>__TARGET__</b> ——&nbsp;红线为链路走向，点击标记查看每跳详情</div>
<div id="map"></div>
<script>
var hops = __DATA__;
var map = L.map('map');
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
  {maxZoom:18, attribution:'&copy; OpenStreetMap'}).addTo(map);
var pts=[];
hops.forEach(function(h){
  var m=L.marker([h.lat,h.lon]).addTo(map);
  m.bindPopup('<b>第'+h.hop+'跳</b><br>'+h.ip+'<br>'+(h.loc||'')+
              '<br>'+(h.isp||'')+'<br>时延 '+h.rtt+' ms');
  pts.push([h.lat,h.lon]);
});
if(pts.length){L.polyline(pts,{color:'red',weight:2,opacity:.8}).addTo(map);
  map.fitBounds(pts,{padding:[60,60]});}
else{map.setView([20,0],2);}
</script></body></html>"""
    return (tpl.replace('__TITLE__', html.escape('UU889 路由地图 · %s' % target))
               .replace('__TARGET__', html.escape(str(target)))
               .replace('__DATA__', data))


# ================================================================== #
#  告警渠道 / 数据入库 / 报表（第三期新增）
# ================================================================== #
DEFAULT_CONFIG = {
    'webhook': {'enabled': False, 'type': 'generic', 'url': ''},
    'email': {'enabled': False, 'host': '', 'port': 465, 'ssl': True,
              'user': '', 'password': '', 'sender': '', 'to': ''},
    'geo': {'mode': 'auto', 'db': ''},
    'allowlist': [],
    'lang': 'zh',
}

def load_config(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    out = {'webhook': dict(DEFAULT_CONFIG['webhook']),
           'email': dict(DEFAULT_CONFIG['email']),
           'geo': dict(DEFAULT_CONFIG['geo']),
           'allowlist': list(DEFAULT_CONFIG['allowlist']),
           'lang': DEFAULT_CONFIG['lang']}
    if isinstance(cfg, dict):
        for k in ('webhook', 'email', 'geo'):
            if isinstance(cfg.get(k), dict):
                out[k].update(cfg[k])
        if isinstance(cfg.get('allowlist'), list):
            out['allowlist'] = cfg['allowlist']
        if isinstance(cfg.get('lang'), str):
            out['lang'] = cfg['lang']
    return out

def save_config(path, cfg):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def db_connect(path):
    conn = sqlite3.connect(path)
    conn.execute('''CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, mode TEXT, kind TEXT, target TEXT, detail TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS cycles(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, mode TEXT, spec TEXT, count INTEGER, changes INTEGER)''')
    conn.execute('CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)')
    if not conn.execute("SELECT v FROM meta WHERE k='device'").fetchone():
        conn.execute("INSERT INTO meta(k,v) VALUES('device',?)", (socket.gethostname(),))
    conn.commit()
    return conn

def db_add_events(conn, rows):
    conn.executemany('INSERT INTO events(ts,mode,kind,target,detail) VALUES(?,?,?,?,?)', rows)
    conn.commit()

def db_add_cycle(conn, ts, mode, spec, count, changes):
    conn.execute('INSERT INTO cycles(ts,mode,spec,count,changes) VALUES(?,?,?,?,?)',
                 (ts, mode, spec, count, changes))
    conn.commit()

def db_fetch_events(conn, limit=2000):
    cur = conn.execute('SELECT ts,mode,kind,target,detail FROM events ORDER BY id DESC LIMIT ?', (limit,))
    return cur.fetchall()

def build_webhook_payload(wtype, text):
    t = (wtype or 'generic').lower()
    if t == 'slack':
        return {'text': text}
    if t == 'dingtalk':
        return {'msgtype': 'text', 'text': {'content': text}}
    if t == 'wechat':
        return {'msgtype': 'text', 'text': {'content': text}}
    if t == 'feishu':
        return {'msg_type': 'text', 'content': {'text': text}}
    if t == 'discord':
        return {'content': text}
    return {'text': text}

def send_webhook(url, wtype, text, timeout=8):
    data = json.dumps(build_webhook_payload(wtype, text)).encode('utf-8')
    req = urllib.request.Request(url, data=data,
        headers={'Content-Type': 'application/json', 'User-Agent': 'UU889/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (True, 'HTTP %s' % resp.getcode())
    except Exception as e:
        return (False, '%s: %s' % (e.__class__.__name__, e))

def build_email_message(cfg, subject, body):
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = cfg.get('sender') or cfg.get('user') or ''
    msg['To'] = cfg.get('to', '')
    return msg

def send_email(cfg, subject, body, timeout=15):
    host = cfg.get('host', '')
    port = int(cfg.get('port') or (465 if cfg.get('ssl') else 25))
    user, pwd = cfg.get('user', ''), cfg.get('password', '')
    sender = cfg.get('sender') or user
    tos = [x for x in re.split(r'[;,\s]+', cfg.get('to', '')) if x]
    if not host or not tos:
        return (False, '邮件配置不完整（缺 SMTP 服务器或收件人）')
    msg = build_email_message(cfg, subject, body)
    try:
        srv = smtplib.SMTP_SSL(host, port, timeout=timeout) if cfg.get('ssl') \
              else smtplib.SMTP(host, port, timeout=timeout)
        if not cfg.get('ssl'):
            try: srv.starttls()
            except Exception: pass
        if user:
            srv.login(user, pwd)
        srv.sendmail(sender, tos, msg.as_string())
        srv.quit()
        return (True, '已发送至 %d 个收件人' % len(tos))
    except Exception as e:
        return (False, '%s: %s' % (e.__class__.__name__, e))

def aggregate_trend(events):
    from collections import OrderedDict
    buckets = OrderedDict()
    for ts, mode, kind, target, detail in sorted(events, key=lambda e: e[0] or ''):
        day = (ts or '')[:10]
        b = buckets.setdefault(day, {'up': 0, 'down': 0})
        if kind in ('上线', '端口开放'):
            b['up'] += 1
        elif kind in ('下线', '端口关闭'):
            b['down'] += 1
    return buckets

def _svg_bar_chart(buckets, width=760, height=230):
    days = list(buckets.keys())
    if not days:
        return '<p style="color:#888">暂无变更数据</p>'
    maxv = max(1, max(max(b['up'], b['down']) for b in buckets.values()))
    pad_l, pad_b, pad_t = 42, 42, 22
    plot_w, plot_h = width - pad_l - 12, height - pad_b - pad_t
    n = len(days); group_w = plot_w / n; bar_w = min(16, group_w / 3)
    p = ['<svg viewBox="0 0 %d %d" width="100%%" style="max-width:%dpx">' % (width, height, width)]
    p.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#ccc"/>' % (pad_l, pad_t, pad_l, pad_t + plot_h))
    p.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#ccc"/>' % (pad_l, pad_t + plot_h, pad_l + plot_w, pad_t + plot_h))
    for i, d in enumerate(days):
        b = buckets[d]; cx = pad_l + i * group_w + group_w / 2
        uh = plot_h * b['up'] / maxv; dh = plot_h * b['down'] / maxv
        p.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="#137333"><title>%s 上线/开放 %d</title></rect>' % (cx - bar_w - 1, pad_t + plot_h - uh, bar_w, uh, d, b['up']))
        p.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="#b00020"><title>%s 下线/关闭 %d</title></rect>' % (cx + 1, pad_t + plot_h - dh, bar_w, dh, d, b['down']))
        p.append('<text x="%.1f" y="%d" font-size="9" text-anchor="middle" fill="#666">%s</text>' % (cx, height - pad_b + 14, d[5:]))
    p.append('<text x="%d" y="%d" font-size="10" fill="#666">max %d</text>' % (pad_l, pad_t - 6, maxv))
    p.append('</svg>')
    return ''.join(p)

def build_report_html(events, title='UU889 监控报表'):
    from collections import Counter
    chart = _svg_bar_chart(aggregate_trend(events))
    total = len(events)
    ups = sum(1 for e in events if e[2] in ('上线', '端口开放'))
    downs = sum(1 for e in events if e[2] in ('下线', '端口关闭'))
    top = Counter(e[3] for e in events).most_common(10)
    rows = ''.join('<tr><td>%s</td><td class="%s">%s</td><td>%s</td><td>%s</td></tr>' % (
        html.escape(str(e[0])), 'up' if e[2] in ('上线','端口开放') else 'down',
        html.escape(str(e[2])), html.escape(str(e[3])), html.escape(str(e[4]))) for e in events[:500])
    toprows = ''.join('<tr><td>%s</td><td>%d</td></tr>' % (html.escape(str(t)), c) for t, c in top)
    gen = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    tpl = """<!DOCTYPE html><html lang=zh><head><meta charset=utf-8><title>__T__</title><style>
body{font-family:sans-serif;margin:24px;color:#222}h1{font-size:20px}h2{font-size:15px;margin-top:22px}
.cards{display:flex;gap:14px;margin:14px 0}.card{background:#f5f7fa;border-radius:8px;padding:12px 18px}
.card b{font-size:22px;display:block}table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}
th,td{border:1px solid #e3e3e3;padding:5px 8px;text-align:left}th{background:#fafafa}
.up{color:#137333}.down{color:#b00020}small{color:#888}
.noprint{margin:0 0 14px}button{padding:8px 14px;font-size:14px;cursor:pointer;border:1px solid #bbb;border-radius:6px;background:#f5f7fa}
@media print{.noprint{display:none}body{margin:6mm}h2{page-break-after:avoid}tr{page-break-inside:avoid}}</style></head><body>
<div class=noprint><button onclick="window.print()">🖨 存为 PDF / 打印（Ctrl 或 ⌘ + P）</button></div>
<h1>__T__</h1><small>生成时间 __G__ ｜ 数据来源 netprobe.db</small>
<div class=cards><div class=card><b>__TOTAL__</b>变更事件</div>
<div class=card><b class=up>__UP__</b>上线/端口开放</div>
<div class=card><b class=down>__DOWN__</b>下线/端口关闭</div></div>
<h2>变更趋势（按天）</h2>__CHART__
<h2>最频繁变更目标 Top 10</h2><table><tr><th>目标</th><th>次数</th></tr>__TOP__</table>
<h2>变更明细（最近 500 条）</h2><table><tr><th>时间</th><th>类型</th><th>目标</th><th>详情</th></tr>__ROWS__</table>
</body></html>"""
    return (tpl.replace('__T__', html.escape(title)).replace('__G__', gen)
               .replace('__TOTAL__', str(total)).replace('__UP__', str(ups))
               .replace('__DOWN__', str(downs)).replace('__CHART__', chart)
               .replace('__TOP__', toprows).replace('__ROWS__', rows))


def db_get_device(conn):
    try:
        row = conn.execute("SELECT v FROM meta WHERE k='device'").fetchone()
        return row[0] if row else ''
    except Exception:
        return ''

def read_db_summary(path):
    """只读方式汇总一个 netprobe.db（不会往外部文件建表）。"""
    device = os.path.basename(path)
    events = []
    try:
        conn = sqlite3.connect(path)
        try:
            row = conn.execute("SELECT v FROM meta WHERE k='device'").fetchone()
            if row and row[0]:
                device = row[0]
        except Exception:
            pass
        try:
            events = conn.execute('SELECT ts,mode,kind,target,detail FROM events '
                                  'ORDER BY id DESC LIMIT 5000').fetchall()
        except Exception:
            events = []
        conn.close()
    except Exception:
        pass
    ups = sum(1 for e in events if e[2] in ('上线', '端口开放'))
    downs = sum(1 for e in events if e[2] in ('下线', '端口关闭'))
    return {'device': device, 'path': path, 'total': len(events),
            'ups': ups, 'downs': downs, 'last_ts': events[0][0] if events else '',
            'events': events}

def build_dashboard_html(sources):
    all_events = []
    for s in sources:
        all_events.extend(s.get('events', []))
    chart = _svg_bar_chart(aggregate_trend(all_events))
    total = sum(s['total'] for s in sources)
    tot_up = sum(s['ups'] for s in sources)
    tot_dn = sum(s['downs'] for s in sources)
    dev_rows = ''.join(
        '<tr><td>%s</td><td><small>%s</small></td><td>%d</td><td class=up>%d</td><td class=down>%d</td><td>%s</td></tr>' % (
            html.escape(str(s['device'])), html.escape(str(s.get('path', ''))),
            s['total'], s['ups'], s['downs'], html.escape(str(s.get('last_ts', '') or '-')))
        for s in sources)
    merged = []
    for s in sources:
        for e in s.get('events', []):
            merged.append((e[0], s['device'], e[2], e[3], e[4]))
    merged.sort(key=lambda r: r[0] or '', reverse=True)
    ev_rows = ''.join(
        '<tr><td>%s</td><td>%s</td><td class="%s">%s</td><td>%s</td><td>%s</td></tr>' % (
            html.escape(str(r[0])), html.escape(str(r[1])),
            'up' if r[2] in ('上线', '端口开放') else 'down',
            html.escape(str(r[2])), html.escape(str(r[3])), html.escape(str(r[4])))
        for r in merged[:400])
    gen = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    tpl = """<!DOCTYPE html><html lang=zh><head><meta charset=utf-8><title>UU889 多设备汇总看板</title><style>
body{font-family:sans-serif;margin:24px;color:#222}h1{font-size:20px}h2{font-size:15px;margin-top:22px}
.cards{display:flex;gap:14px;margin:14px 0;flex-wrap:wrap}.card{background:#f5f7fa;border-radius:8px;padding:12px 18px}
.card b{font-size:22px;display:block}table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}
th,td{border:1px solid #e3e3e3;padding:5px 8px;text-align:left}th{background:#fafafa}
.up{color:#137333}.down{color:#b00020}small{color:#888}
.noprint{margin:0 0 14px}button{padding:8px 14px;font-size:14px;cursor:pointer;border:1px solid #bbb;border-radius:6px;background:#f5f7fa}
@media print{.noprint{display:none}body{margin:6mm}tr{page-break-inside:avoid}}</style></head><body>
<div class=noprint><button onclick="window.print()">🖨 存为 PDF / 打印（Ctrl 或 ⌘ + P）</button></div>
<h1>UU889 多设备汇总看板</h1><small>生成时间 __G__ ｜ __N__ 台设备</small>
<div class=cards><div class=card><b>__DEV__</b>设备</div><div class=card><b>__TOTAL__</b>变更事件</div>
<div class=card><b class=up>__UP__</b>上线/端口开放</div><div class=card><b class=down>__DOWN__</b>下线/端口关闭</div></div>
<h2>各设备概览</h2><table><tr><th>设备</th><th>数据库路径</th><th>事件数</th><th>上线/开放</th><th>下线/关闭</th><th>最近事件</th></tr>__DEVROWS__</table>
<h2>合并变更趋势（按天）</h2>__CHART__
<h2>合并变更明细（最近 400 条）</h2><table><tr><th>时间</th><th>设备</th><th>类型</th><th>目标</th><th>详情</th></tr>__EVROWS__</table>
</body></html>"""
    return (tpl.replace('__G__', gen).replace('__N__', str(len(sources)))
               .replace('__DEV__', str(len(sources))).replace('__TOTAL__', str(total))
               .replace('__UP__', str(tot_up)).replace('__DOWN__', str(tot_dn))
               .replace('__DEVROWS__', dev_rows).replace('__CHART__', chart)
               .replace('__EVROWS__', ev_rows))


# ------------------ 第五期：诊断 / IPv6 / 离线地理 / 授权 / CLI ------------------
_GEO = {'mode': 'auto', 'db': ''}   # 离线地理库配置（mode: auto/online/offline, db: mmdb 路径）


def set_geo_config(mode='auto', db=''):
    _GEO['mode'] = mode or 'auto'
    _GEO['db'] = db or ''


def _is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _family_for(ip):
    return socket.AF_INET6 if ':' in ip else socket.AF_INET


# ===== 纯标准库 MaxMind/DB-IP MMDB 读取器（离线地理库，无需第三方 geoip2） =====
_MMDB_META_MARKER = b'\xab\xcd\xefMaxMind.com'


class _MMDBDecoder:
    def __init__(self, buf, pointer_base=0):
        self.buf = buf
        self.pb = pointer_base

    def decode(self, offset):
        ctrl = self.buf[offset]
        offset += 1
        typ = ctrl >> 5
        if typ == 1:  # pointer
            psize = ((ctrl >> 3) & 0x3) + 1
            pb = self.buf[offset:offset + psize]
            new = offset + psize
            if psize == 4:
                val = int.from_bytes(pb, 'big')
            else:
                val = int.from_bytes(bytes([ctrl & 0x7]) + pb, 'big')
            val += (0, 2048, 526336, 0)[psize - 1] + self.pb
            return self.decode(val)[0], new
        if typ == 0:  # extended
            typ = 7 + self.buf[offset]
            offset += 1
        size = ctrl & 0x1f
        if size == 29:
            size = 29 + self.buf[offset]; offset += 1
        elif size == 30:
            size = 285 + int.from_bytes(self.buf[offset:offset + 2], 'big'); offset += 2
        elif size == 31:
            size = 65821 + int.from_bytes(self.buf[offset:offset + 3], 'big'); offset += 3
        b = self.buf
        if typ == 2:   # utf8 string
            return bytes(b[offset:offset + size]).decode('utf-8', 'replace'), offset + size
        if typ == 7:   # map
            out = {}; off = offset
            for _ in range(size):
                k, off = self.decode(off)
                v, off = self.decode(off)
                out[k] = v
            return out, off
        if typ in (5, 6, 9, 10):  # uint16/32/64/128
            return int.from_bytes(b[offset:offset + size], 'big'), offset + size
        if typ == 8:   # int32
            v = int.from_bytes(b[offset:offset + size], 'big')
            if size and (b[offset] & 0x80):
                v -= 1 << (size * 8)
            return v, offset + size
        if typ == 11:  # array
            arr = []; off = offset
            for _ in range(size):
                v, off = self.decode(off); arr.append(v)
            return arr, off
        if typ == 14:  # bool
            return size != 0, offset
        if typ == 15:  # float
            return struct.unpack('>f', b[offset:offset + 4])[0], offset + 4
        if typ == 3:   # double
            return struct.unpack('>d', b[offset:offset + 8])[0], offset + 8
        if typ == 4:   # bytes
            return bytes(b[offset:offset + size]), offset + size
        raise ValueError('mmdb bad type %d' % typ)


class MMDB:
    """只读的 MMDB 查询器；用 mmap 避免把上百 MB 数据全部读进内存。"""
    def __init__(self, path):
        self._f = open(path, 'rb')
        self.buf = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        i = self.buf.rfind(_MMDB_META_MARKER)
        if i < 0:
            raise ValueError('不是有效的 MMDB 文件')
        mstart = i + len(_MMDB_META_MARKER)
        meta, _ = _MMDBDecoder(self.buf, mstart).decode(mstart)
        self.meta = meta
        self.node_count = meta['node_count']
        self.record_size = meta['record_size']
        self.ip_version = meta['ip_version']
        self.node_bytes = self.record_size * 2 // 8
        self.tree_size = self.node_count * self.node_bytes
        self.dec = _MMDBDecoder(self.buf, self.tree_size + 16)
        self._v4start = None

    def _read_node(self, node, index):
        base = node * self.node_bytes
        b = self.buf
        rs = self.record_size
        if rs == 28:
            if index == 0:
                return ((b[base + 3] & 0xf0) << 20) | int.from_bytes(b[base:base + 3], 'big')
            return ((b[base + 3] & 0x0f) << 24) | int.from_bytes(b[base + 4:base + 7], 'big')
        if rs == 24:
            off = base + index * 3
            return int.from_bytes(b[off:off + 3], 'big')
        if rs == 32:
            off = base + index * 4
            return int.from_bytes(b[off:off + 4], 'big')
        raise ValueError('mmdb record_size %d' % rs)

    def _start_node(self, bits):
        if self.ip_version != 6 or bits == 128:
            return 0
        if self._v4start is not None:
            return self._v4start
        node = 0
        for _ in range(96):
            if node >= self.node_count:
                break
            node = self._read_node(node, 0)
        self._v4start = node
        return node

    def get(self, ip):
        packed = ipaddress.ip_address(ip).packed
        bits = len(packed) * 8
        node = self._start_node(bits)
        nc = self.node_count
        for i in range(bits):
            if node >= nc:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._read_node(node, bit)
        if node == nc:
            return None
        if node > nc:
            rec = self.dec.decode((node - nc) + self.tree_size)[0]
            return rec if isinstance(rec, dict) else None
        return None

    def close(self):
        try:
            self.buf.close()
        except Exception:
            pass
        try:
            self._f.close()
        except Exception:
            pass


GEO_DBIP_URL = 'https://download.db-ip.com/free/dbip-city-lite-%s.mmdb.gz'


def default_geodb_path(data_dir):
    return os.path.join(data_dir, 'geo', 'dbip-city-lite.mmdb')


def download_geodb(dest, progress=None, months_back=4):
    """下载 DB-IP City Lite（免费、可再分发，CC-BY-4.0）并解压为 .mmdb。progress(done,total,tag)."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    import datetime as _dt
    today = _dt.date.today()
    tried = []
    for k in range(months_back):
        y, m = today.year, today.month - k
        while m <= 0:
            m += 12; y -= 1
        tag = '%04d-%02d' % (y, m)
        tried.append(tag)
        url = GEO_DBIP_URL % tag
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'UU889/1.0'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                total = int(resp.headers.get('Content-Length') or 0)
                gz_tmp = dest + '.gz.part'
                done = 0
                with open(gz_tmp, 'wb') as f:
                    while True:
                        chunk = resp.read(131072)
                        if not chunk:
                            break
                        f.write(chunk)
                        done += len(chunk)
                        if progress:
                            progress(done, total, tag)
            out_tmp = dest + '.part'
            with gzip.open(gz_tmp, 'rb') as gz, open(out_tmp, 'wb') as out:
                while True:
                    blk = gz.read(1 << 20)
                    if not blk:
                        break
                    out.write(blk)
            if os.path.exists(dest):
                try:
                    os.remove(dest)
                except OSError:
                    pass
            os.replace(out_tmp, dest)
            try:
                os.remove(gz_tmp)
            except OSError:
                pass
            return dest
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            raise
    raise RuntimeError('下载失败（已尝试月份：%s）' % ', '.join(tried))


_GEO_READERS = {}


def _get_mmdb(path):
    if not path or not os.path.exists(path):
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (st.st_mtime, st.st_size)
    cached = _GEO_READERS.get(path)
    if cached and cached[0] == key:
        return cached[1]
    try:
        rd = MMDB(path)
    except Exception:
        return None
    _GEO_READERS[path] = (key, rd)
    return rd


def _geo_name(d):
    n = (d or {}).get('names') or {}
    return n.get('zh-CN') or n.get('en') or (next(iter(n.values()), '') if n else '')


def geo_offline(ip, db_path):
    """用内置 MMDB 读取器做离线定位（支持 DB-IP City Lite / MaxMind GeoLite2）。失败返回 None。"""
    rd = _get_mmdb(db_path)
    if rd is None:
        return None
    try:
        rec = rd.get(ip)
    except Exception:
        rec = None
    if not isinstance(rec, dict):
        return None
    subs = rec.get('subdivisions') or []
    loc = rec.get('location') or {}
    return {'ip': ip, 'status': 'success',
            'country': _geo_name(rec.get('country')),
            'region': _geo_name(subs[0]) if subs else '',
            'city': _geo_name(rec.get('city')),
            'isp': '', 'org': '', 'asn': '',
            'lat': loc.get('latitude'), 'lon': loc.get('longitude')}


def dns_lookup(host):
    """DNS 正向(域名→IP, A/AAAA)与反向(IP→PTR)解析。"""
    out = {'query': host, 'forward': [], 'reverse': '', 'error': ''}
    if _is_ip(host):
        out['forward'] = [host]
        try:
            out['reverse'] = socket.gethostbyaddr(host)[0]
        except Exception as e:
            out['error'] = 'PTR: %s' % e.__class__.__name__
        return out
    try:
        out['forward'] = sorted(set(i[4][0] for i in socket.getaddrinfo(host, None)))
        if out['forward']:
            try:
                out['reverse'] = socket.gethostbyaddr(out['forward'][0])[0]
            except Exception:
                pass
    except Exception as e:
        out['error'] = '%s: %s' % (e.__class__.__name__, e)
    return out


def tls_check(host, port=443, timeout=8):
    """TLS 证书检查：主体/颁发者/有效期/剩余天数/SAN/协议版本。"""
    res = {'host': host, 'port': int(port), 'ok': False, 'error': '', 'subject': '',
           'issuer': '', 'not_after': '', 'days_left': None, 'san': [], 'version': ''}
    try:
        ctx = ssl.create_default_context()
        if _is_ip(host):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sni = None if _is_ip(host) else host
            with ctx.wrap_socket(sock, server_hostname=sni) as ss:
                cert = ss.getpeercert()
                res['version'] = ss.version()
        if cert:
            subj = dict(x[0] for x in cert.get('subject', ()))
            iss = dict(x[0] for x in cert.get('issuer', ()))
            res['subject'] = subj.get('commonName', '')
            res['issuer'] = iss.get('commonName', '') or iss.get('organizationName', '')
            res['not_after'] = cert.get('notAfter', '')
            try:
                exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                res['days_left'] = (exp - datetime.utcnow()).days
            except Exception:
                pass
            res['san'] = [v for (t, v) in cert.get('subjectAltName', ()) if t == 'DNS']
        res['ok'] = True
    except ssl.SSLCertVerificationError as e:
        res['error'] = '证书校验失败: %s' % (getattr(e, 'verify_message', '') or e)
    except Exception as e:
        res['error'] = '%s: %s' % (e.__class__.__name__, e)
    return res


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def http_check(url, timeout=10, max_redirects=5):
    """HTTP(S) 检查：状态码、响应耗时、重定向次数、Server 头；https 附带 TLS 信息。"""
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    res = {'url': url, 'ok': False, 'status': None, 'reason': '', 'elapsed_ms': None,
           'final_url': url, 'redirects': 0, 'server': '', 'error': '', 'tls': None}
    cur, seen, t0 = url, 0, time.time()
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        while True:
            req = urllib.request.Request(cur, headers={'User-Agent': 'UU889/1.0'}, method='GET')
            try:
                resp = opener.open(req, timeout=timeout)
                res.update(status=resp.getcode(), reason=getattr(resp, 'reason', ''),
                           server=resp.headers.get('Server', ''), final_url=cur, ok=True)
                resp.read(64)
                resp.close()
                break
            except urllib.error.HTTPError as he:
                if he.code in (301, 302, 303, 307, 308) and seen < max_redirects and he.headers.get('Location'):
                    cur = urllib.parse.urljoin(cur, he.headers.get('Location'))
                    seen += 1
                    continue
                res.update(status=he.code, reason=he.reason, final_url=cur, ok=True)
                break
    except Exception as e:
        res['error'] = '%s: %s' % (e.__class__.__name__, e)
    res['elapsed_ms'] = round((time.time() - t0) * 1000, 1)
    res['redirects'] = seen
    if res['final_url'].startswith('https://'):
        u = urllib.parse.urlparse(res['final_url'])
        res['tls'] = tls_check(u.hostname, u.port or 443)
    return res


def ping_quality(ip, count=5, timeout_ms=1000):
    """连发 count 次 Ping，统计丢包率、最小/平均/最大时延与抖动(jitter)。"""
    rtts, recv = [], 0
    for _ in range(count):
        r = ping_host(ip, timeout_ms)
        if r['alive']:
            recv += 1
            if r['rtt_ms'] is not None:
                rtts.append(r['rtt_ms'])
    sent = count
    return {'ip': ip, 'sent': sent, 'recv': recv,
            'loss_pct': round(100.0 * (sent - recv) / sent, 1) if sent else 0.0,
            'min': min(rtts) if rtts else None, 'max': max(rtts) if rtts else None,
            'avg': round(statistics.mean(rtts), 2) if rtts else None,
            'jitter': round(statistics.pstdev(rtts), 2) if len(rtts) > 1 else 0.0}


def check_authorized(targets, allowlist):
    """授权白名单校验：allowlist 为 CIDR 列表，空=不限制。返回 (是否全部授权, [越权目标])。"""
    nets = []
    for c in allowlist or []:
        c = c.strip()
        if not c:
            continue
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            pass
    if not nets:
        return (True, [])
    bad = []
    for t in targets:
        try:
            ip = ipaddress.ip_address(t)
            if not any(ip.version == n.version and ip in n for n in nets):
                bad.append(t)
        except Exception:
            bad.append(t)
    return (len(bad) == 0, bad)


def audit_log(path, action, detail):
    """审计日志：时间 / 操作系统用户 / 动作 / 详情，追加写入。"""
    try:
        with open(path, 'a', encoding='utf-8') as f:
            f.write('%s\t%s\t%s\t%s\n' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                          getpass.getuser(), action, detail))
    except Exception:
        pass


def fast_scan(targets, ports, timeout=1.0, max_inflight=400, on_result=None, stop=None):
    """高并发 TCP connect 扫描（selectors 非阻塞单线程流水线，masscan 式）。返回开放列表。"""
    tasks = [(ip, p) for ip in targets for p in ports]
    results = []
    sel = selectors.DefaultSelector()
    it = iter(tasks)
    pending = {}

    def _open(ip, port):
        r = {'ip': ip, 'port': port, 'proto': 'TCP', 'state': 'open',
             'service': COMMON_PORTS.get(port, ''), 'banner': ''}
        results.append(r)
        if on_result:
            on_result(r)

    def _finish(s):
        try:
            fd = s.fileno()
        except Exception:
            fd = None
        try:
            sel.unregister(s)
        except Exception:
            pass
        if fd is not None:
            pending.pop(fd, None)
        try:
            s.close()
        except Exception:
            pass

    def launch():
        try:
            ip, port = next(it)
        except StopIteration:
            return False
        try:
            s = socket.socket(_family_for(ip), socket.SOCK_STREAM)
            s.setblocking(False)
            rc = s.connect_ex((ip, port))
        except Exception:
            return True
        if rc == 0:
            _open(ip, port); s.close(); return True
        if rc in (errno.EINPROGRESS, errno.EWOULDBLOCK, 10035, 115):
            try:
                sel.register(s, selectors.EVENT_WRITE, (ip, port, time.time() + timeout))
                pending[s.fileno()] = (s, ip, port, time.time() + timeout)
            except Exception:
                s.close()
        else:
            s.close()
        return True

    for _ in range(max_inflight):
        if not launch():
            break
    while pending:
        if stop is not None and stop.is_set():
            break
        for key, _mask in sel.select(timeout=0.3):
            s = key.fileobj
            ip, port, _dl = key.data
            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            _finish(s)
            if err == 0:
                _open(ip, port)
            launch()
        now = time.time()
        for fd, (s, ip, port, dl) in list(pending.items()):
            if now > dl:
                _finish(s)
                launch()
    sel.close()
    return results


def _checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff


def _build_syn(src_ip, dst_ip, src_port, dst_port, seq=0):
    off_flags = (5 << 12) | 0x02  # data offset 5 words, SYN
    hdr = struct.pack('!HHIIHHHH', src_port, dst_port, seq, 0, off_flags, 5840, 0, 0)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(hdr))
    chk = _checksum(pseudo + hdr)
    return struct.pack('!HHIIHHHH', src_port, dst_port, seq, 0, off_flags, 5840, chk, 0)


def _local_ip_for(dst):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '0.0.0.0'


def _parse_tcp_response(data):
    """解析 raw IPPROTO_TCP 收到的字节(含IP头) -> (src_ip, src_port, dst_port, flags)。"""
    ihl = (data[0] & 0x0f) * 4
    src_ip = socket.inet_ntoa(data[12:16])
    tcp = data[ihl:]
    src_port, dst_port = struct.unpack('!HH', tcp[0:4])
    flags = tcp[13]
    return src_ip, src_port, dst_port, flags


def syn_scan(targets, ports, timeout=2.0, on_result=None):
    """完整 SYN 半开扫描：发 SYN，嗅探 SYN-ACK(开放)/RST(关闭)。需 root，仅 Linux/macOS。"""
    if IS_WINDOWS:
        raise RuntimeError('Windows 不支持原始套接字 SYN 扫描')
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        raise RuntimeError('SYN 扫描需要 root 权限（sudo）')
    try:
        send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv.settimeout(0.5)
    except Exception as e:
        raise RuntimeError('无法创建原始套接字: %s' % e)
    results = []
    src_port = random.randint(1025, 60000)
    pending = set()
    try:
        for ip in targets:
            src_ip = _local_ip_for(ip)
            for port in ports:
                try:
                    send.sendto(_build_syn(src_ip, ip, src_port, port), (ip, port))
                    pending.add((ip, port))
                except Exception:
                    pass
        deadline = time.time() + timeout
        while pending and time.time() < deadline:
            try:
                data, _addr = recv.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                sip, sport, dport, flags = _parse_tcp_response(data)
            except Exception:
                continue
            if dport != src_port:
                continue
            key = (sip, sport)
            if key in pending:
                pending.discard(key)
                if (flags & 0x12) == 0x12:
                    r = {'ip': sip, 'port': sport, 'proto': 'TCP', 'state': 'open',
                         'service': COMMON_PORTS.get(sport, ''), 'banner': ''}
                    results.append(r)
                    if on_result:
                        on_result(r)
    finally:
        send.close()
        recv.close()
    return results


_ALIVE_PORTS = [80, 443, 22, 3389, 445]


def smart_alive(ip, timeout_ms=1000):
    """智能存活：先 ICMP，禁 Ping 主机再用 TCP 探常见端口（open/closed 都算存活）。"""
    r = ping_host(ip, timeout_ms)
    if r['alive']:
        r['method'] = 'icmp'
        return r
    for port in _ALIVE_PORTS:
        st = scan_tcp(ip, port, timeout=timeout_ms / 1000.0)['state']
        if st in ('open', 'closed'):
            return {'ip': ip, 'alive': True, 'rtt_ms': None, 'ttl': None, 'method': 'tcp:%d' % port}
    return {'ip': ip, 'alive': False, 'rtt_ms': None, 'ttl': None, 'method': ''}


RISK_PORTS = {
    21: ('中', 'FTP 明文传输'), 23: ('高', 'Telnet 明文，强烈建议关闭'),
    69: ('中', 'TFTP 无认证'), 161: ('中', 'SNMP 常用弱 community'),
    445: ('高', 'SMB 暴露(勒索/漏洞高发)'),
    1433: ('高', 'MSSQL 数据库暴露'), 1521: ('高', 'Oracle 暴露'),
    2375: ('高', 'Docker API 未授权=主机沦陷'), 2379: ('高', 'etcd 暴露'),
    3306: ('高', 'MySQL 数据库暴露'), 3389: ('高', 'RDP 远程桌面暴露'),
    5432: ('高', 'PostgreSQL 暴露'), 5601: ('中', 'Kibana 暴露'),
    5900: ('中', 'VNC 远程桌面'), 5985: ('中', 'WinRM'),
    6379: ('高', 'Redis 常无认证'), 9200: ('高', 'Elasticsearch 常无认证'),
    11211: ('高', 'Memcached 无认证/放大攻击'), 15672: ('中', 'RabbitMQ 管理台'),
    27017: ('高', 'MongoDB 暴露'),
}


def risk_note(port):
    return RISK_PORTS.get(port, ('', ''))


def qmon_stats(data):
    """链路质量滚动统计：data 为 RTT 列表(None=丢包)。"""
    rtts = [x for x in data if x is not None]
    n, recv = len(data), len(rtts)
    return {'n': n, 'recv': recv,
            'loss_pct': round(100.0 * (n - recv) / n, 1) if n else 0.0,
            'min': round(min(rtts), 2) if rtts else None,
            'max': round(max(rtts), 2) if rtts else None,
            'avg': round(statistics.mean(rtts), 2) if rtts else None,
            'jitter': round(statistics.pstdev(rtts), 2) if len(rtts) > 1 else 0.0}


_SPARK = ' ▁▂▃▄▅▆▇█'


def sparkline(vals):
    nums = [v for v in vals if v is not None]
    if not nums:
        return ''
    lo, hi = min(nums), max(nums)
    rng = (hi - lo) or 1.0
    out = ''
    for v in vals:
        if v is None:
            out += '✗'
        else:
            idx = int((v - lo) / rng * 7) + 1
            out += _SPARK[min(8, max(1, idx))]
    return out


_SIGS = [
    (re.compile(rb'SSH-[\d.]+-(\S+)'), 'SSH'),
    (re.compile(rb'^220[- ].*?(?:FTP|FileZilla|vsFTPd|ProFTPD)', re.I), 'FTP'),
    (re.compile(rb'^220[- ].*?(?:SMTP|ESMTP|Postfix|Exim)', re.I), 'SMTP'),
    (re.compile(rb'^\+OK', re.I), 'POP3'),
    (re.compile(rb'^\* OK.*IMAP', re.I), 'IMAP'),
    (re.compile(rb'Server:\s*([^\r\n]+)', re.I), 'HTTP'),
    (re.compile(rb'-ERR|(\+PONG)|Redis', re.I), 'Redis'),
    (re.compile(rb'RFB \d'), 'VNC'),
]


def _probe_for(port):
    if port == 6379:
        return b'PING\r\n'
    # 默认发 HTTP GET：banner-first 服务(SSH/FTP/SMTP)已在首次 recv 返回，
    # 需要请求才应答的服务(HTTP，任意端口)则据此拿到 Server 头。
    return b'GET / HTTP/1.0\r\nHost: probe\r\nUser-Agent: UU889\r\n\r\n'


def probe_service(ip, port, timeout=2.0):
    """连接开放 TCP 端口，抓 banner / 发探针，识别服务与版本。"""
    banner = b''
    try:
        s = socket.socket(_family_for(ip), socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return {'ip': ip, 'port': port, 'service': COMMON_PORTS.get(port, ''),
                    'product': '', 'version': '', 'banner': ''}
        try:
            s.settimeout(timeout)
            banner = s.recv(256)
        except socket.timeout:
            banner = b''
        if not banner:
            try:
                s.sendall(_probe_for(port))
                s.settimeout(timeout)
                banner = s.recv(512)
            except Exception:
                banner = b''
        s.close()
    except Exception:
        pass
    product, version = '', ''
    for rx, name in _SIGS:
        m = rx.search(banner)
        if m:
            product = name
            try:
                g = m.group(1)
                if g:
                    version = g.decode('latin-1', 'ignore').strip()
            except Exception:
                pass
            break
    text = banner.decode('latin-1', 'ignore').strip().replace('\r', ' ').replace('\n', ' ')
    return {'ip': ip, 'port': port, 'service': COMMON_PORTS.get(port, ''),
            'product': product, 'version': version, 'banner': text[:180]}


def _ping_df(host, payload, timeout=2):
    if IS_WINDOWS:
        cmd = ['ping', '-n', '1', '-f', '-l', str(payload), '-w', str(int(timeout * 1000)), host]
    elif IS_MAC:
        cmd = ['ping', '-c', '1', '-D', '-s', str(payload), host]
    else:
        cmd = ['ping', '-c', '1', '-M', 'do', '-s', str(payload), '-W', str(max(1, int(timeout))), host]
    try:
        pr = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2, creationflags=_NO_WINDOW)
        out = (pr.stdout + pr.stderr).decode('utf-8', 'ignore').lower()
        if pr.returncode == 0 and 'ttl=' in out and not any(w in out for w in ('frag', 'too long', 'exceeds', 'message too')):
            return True
        return False
    except Exception:
        return False


def discover_mtu(host, low=576, high=1500, timeout=2):
    """用 DF 位 ping 二分探测到 host 的路径 MTU。"""
    ip = resolve_host(host) or host
    if not _ping_df(ip, low - 28, timeout):
        return {'host': host, 'ip': ip, 'mtu': None,
                'note': '无法用 DF ping 探测（主机不可达或过滤 ICMP/DF）'}
    lo, hi = low, high
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _ping_df(ip, mid - 28, timeout):
            lo = mid
        else:
            hi = mid - 1
    return {'host': host, 'ip': ip, 'mtu': lo, 'note': ''}


PANEL_HTML = """<!DOCTYPE html><html lang=zh><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>UU889 面板</title><style>
body{font-family:sans-serif;margin:0;background:#f5f7fa;color:#222}
header{background:#137333;color:#fff;padding:12px 18px;font-size:18px}
.wrap{max-width:900px;margin:18px auto;padding:0 14px}
.card{background:#fff;border-radius:8px;padding:14px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:14px}
input{padding:6px 8px;border:1px solid #ccc;border-radius:5px}
button{padding:6px 12px;margin:3px;border:1px solid #bbb;border-radius:6px;background:#eef;cursor:pointer}
pre{background:#0b1021;color:#c8e1ff;padding:12px;border-radius:6px;overflow:auto;max-height:60vh}
label{font-size:13px;color:#555}</style></head><body>
<header>&#128225; UU889 网络测试面板</header>
<div class=wrap>
<div class=card>
<div><label>目标</label> <input id=target size=28 value="127.0.0.1"> &nbsp;
<label>端口</label> <input id=ports size=14 value="top"> &nbsp;
<label>Token</label> <input id=token size=10></div>
<div style="margin-top:8px">
<button onclick="run('ping')">存活 Ping</button>
<button onclick="run('scan','ports')">端口扫描</button>
<button onclick="run('dns')">DNS</button>
<button onclick="run('http','url')">HTTP</button>
<button onclick="run('tls')">TLS</button>
<button onclick="run('quality')">Ping质量</button>
<button onclick="run('mtu')">MTU</button>
</div></div>
<div class=card><b id=st>就绪</b><pre id=out>结果会显示在这里…</pre></div>
</div>
<script>
function q(){var t=document.getElementById('token').value;return t?('&token='+encodeURIComponent(t)):''}
function run(ep,extra){
 var tgt=encodeURIComponent(document.getElementById('target').value);
 var u='/'+ep+'?target='+tgt+'&host='+tgt+'&url='+tgt;
 if(extra==='ports')u+='&ports='+encodeURIComponent(document.getElementById('ports').value);
 u+=q();
 document.getElementById('st').textContent='请求中… '+ep;
 fetch(u).then(r=>r.json()).then(d=>{
   document.getElementById('st').textContent=ep+' 完成';
   document.getElementById('out').textContent=JSON.stringify(d,null,2);
 }).catch(e=>{document.getElementById('st').textContent='出错';document.getElementById('out').textContent=e});
}
</script></body></html>"""


def run_server(host='127.0.0.1', port=8899, token='', allowlist=None, audit_path=None):
    """常驻 HTTP JSON API + 浏览器面板。GET / 面板；/health /ping /scan /dns /http /tls /quality /mtu 。默认仅监听本机。"""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def _send(self, code, obj, ctype='application/json; charset=utf-8'):
            body = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            path = u.path.strip('/')
            g1 = lambda k, d='': (q.get(k, [d])[0])
            if path in ('', 'ui', 'index.html'):
                self._send(200, PANEL_HTML.encode('utf-8'), 'text/html; charset=utf-8')
                return
            if token and self.headers.get('X-Token') != token and g1('token') != token:
                self._send(401, {'error': 'unauthorized'})
                return
            try:
                if path == 'health':
                    self._send(200, {'ok': True, 'service': 'UU889 API'}); return
                if path in ('ping', 'scan', 'quality', 'trace'):
                    targets = expand_targets(g1('target'))
                    if allowlist is not None:
                        ok, bad = check_authorized(targets, allowlist)
                        if not ok:
                            self._send(403, {'error': 'forbidden', 'offending': bad}); return
                if path == 'ping':
                    import concurrent.futures as cf
                    with cf.ThreadPoolExecutor(max_workers=64) as ex:
                        res = list(ex.map(lambda ip: ping_host(ip, 1000), targets))
                    self._send(200, res)
                elif path == 'scan':
                    ports = parse_ports(g1('ports', 'top'))
                    res = fast_scan(targets, ports, timeout=float(g1('timeout', '1')))
                    for r in res:
                        lvl, reason = risk_note(r['port'])
                        if lvl:
                            r['risk'], r['risk_note'] = lvl, reason
                    self._send(200, res)
                elif path == 'dns':
                    self._send(200, dns_lookup(g1('host') or g1('target')))
                elif path == 'http':
                    self._send(200, http_check(g1('url')))
                elif path == 'tls':
                    self._send(200, tls_check(g1('host'), int(g1('port', '443'))))
                elif path == 'quality':
                    self._send(200, ping_quality(targets[0], int(g1('count', '5'))))
                elif path == 'mtu':
                    self._send(200, discover_mtu(g1('host') or g1('target')))
                else:
                    self._send(404, {'error': 'unknown endpoint'}); return
                if audit_path:
                    audit_log(audit_path, 'API:' + path, u.query[:120])
            except Exception as e:
                self._send(500, {'error': str(e)})

        def log_message(self, *a):
            pass

    return ThreadingHTTPServer((host, port), H)


def _icon_png(size=64, bg=(37, 99, 235), fg=(255, 255, 255)):
    S = size
    cx = S / 2.0
    t = S * 0.14
    Wo = S * 0.26
    Wi = Wo - t
    yt = S * 0.24
    yc = S * 0.58
    rr = S * 0.22  # 圆角半径
    rows = []
    for y in range(S):
        row = bytearray()
        for x in range(S):
            # 圆角背景 alpha
            a = 255
            for (ccx, ccy) in ((rr, rr), (S - rr, rr), (rr, S - rr), (S - rr, S - rr)):
                if ((x < rr and ccx == rr) or (x > S - rr and ccx == S - rr)) and \
                   ((y < rr and ccy == rr) or (y > S - rr and ccy == S - rr)):
                    if math.hypot(x + 0.5 - ccx, y + 0.5 - ccy) > rr:
                        a = 0
            # U 笔画判定
            inU = False
            dx = abs(x + 0.5 - cx)
            if yt <= y <= yc:
                inU = Wi <= dx <= Wo
            elif y > yc:
                d = math.hypot(x + 0.5 - cx, y + 0.5 - yc)
                inU = (Wi <= d <= Wo) and (y <= yc + Wo + 1)
            if inU and a:
                row += bytes(fg) + b'\xff'
            else:
                row += bytes(bg) + bytes([a])
        rows.append(bytes(row))

    def chunk(typ, data):
        return struct.pack('!I', len(data)) + typ + data + struct.pack('!I', zlib.crc32(typ + data) & 0xffffffff)
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr = struct.pack('!IIBBBBB', S, S, 8, 6, 0, 0, 0)
    raw = b''.join(b'\x00' + r for r in rows)
    return sig + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b'')


def make_ico(path, sizes=(256, 64, 48, 32, 16)):
    imgs = [(s, _icon_png(s)) for s in sizes]
    n = len(imgs)
    hdr = struct.pack('<HHH', 0, 1, n)
    ent = b''
    body = b''
    off = 6 + n * 16
    for s, png in imgs:
        w = 0 if s >= 256 else s
        ent += struct.pack('<BBBBHHII', w, w, 0, 0, 1, 32, len(png), off)
        body += png
        off += len(png)
    open(path, 'wb').write(hdr + ent + body)
    return path


def is_open_like(state, proto='TCP'):
    # 只有“确认开放”才算开放：TCP 建连成功 / UDP 收到应答 => state=='open'。
    # UDP 无响应记为 open|filtered（未知），**不计为开放**，否则整段 UDP 会被误报为开放。
    return state == 'open'


_OUI = {
    '00:00:0c': 'Cisco', '00:1a:a0': 'Dell', '00:50:56': 'VMware', '00:0c:29': 'VMware',
    '00:1c:42': 'Parallels', '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
    'b8:27:eb': 'RaspberryPi', 'dc:a6:32': 'RaspberryPi', 'e4:5f:01': 'RaspberryPi',
    '3c:5a:b4': 'Google', 'f4:f5:e8': 'Google', '00:1a:11': 'Google',
    'fc:fb:fb': 'Cisco', '00:25:9c': 'Cisco', 'a4:5e:60': 'Apple', '3c:15:c2': 'Apple',
    'f0:18:98': 'Apple', '00:16:3e': 'Xen', '00:15:5d': 'Microsoft/Hyper-V',
    'd4:3d:7e': 'MSI', '00:e0:4c': 'Realtek', '00:1d:0f': 'TP-Link', '50:c7:bf': 'TP-Link',
    'ac:84:c6': 'TP-Link', '00:24:e4': 'Withings', '18:fe:34': 'Espressif', '24:0a:c4': 'Espressif',
    '8c:aa:b5': 'Espressif', '30:ae:a4': 'Espressif', 'b4:e6:2d': 'Espressif',
    '00:0e:c6': 'ASIX', '00:1b:63': 'Apple', '90:9a:4a': 'TP-Link', 'ec:08:6b': 'TP-Link',
    'c8:3a:35': 'Tenda', '00:1f:3f': 'AVM', '00:04:20': 'Slim',
}


def mac_vendor(mac):
    return _OUI.get(mac.lower()[:8], '')


def arp_table():
    """读取本机 ARP/邻居表：IP↔MAC（+厂商）。跨平台解析 ip neigh / arp -a。"""
    if not IS_WINDOWS and not IS_MAC:
        cmds = [['ip', 'neigh'], ['arp', '-a', '-n'], ['arp', '-a']]
    else:
        cmds = [['arp', '-a']]
    out = ''
    for c in cmds:
        try:
            pr = subprocess.run(c, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=6, creationflags=_NO_WINDOW)
            out = pr.stdout.decode('utf-8', 'ignore') + pr.stderr.decode('utf-8', 'ignore')
            if out.strip():
                break
        except Exception:
            continue
    rows = []
    seen = set()
    for line in out.splitlines():
        ipm = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        macm = re.search(r'([0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(?:\2[0-9a-fA-F]{2}){4})', line)
        if ipm and macm:
            ip = ipm.group(1)
            mac = macm.group(1).replace('-', ':').lower()
            if mac in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
                continue
            key = (ip, mac)
            if key in seen:
                continue
            seen.add(key)
            rows.append({'ip': ip, 'mac': mac, 'vendor': mac_vendor(mac)})
    return rows


def ip_info(target, timeout=5):
    """IP 归属地：域名→全部 A/AAAA，每个 IP 附 rDNS + 国家/地区/城市/ISP/AS。"""
    out = {'query': target, 'records': [], 'error': ''}
    try:
        ipaddress.ip_address(target)
        ips = [target]
    except ValueError:
        try:
            ips = sorted(set(i[4][0] for i in socket.getaddrinfo(target, None)))
        except Exception as e:
            out['error'] = '%s: %s' % (e.__class__.__name__, e)
            return out
    for ip in ips:
        rdns = ''
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        g = geolocate(ip, timeout=timeout)
        out['records'].append({'ip': ip, 'family': 'IPv6' if ':' in ip else 'IPv4', 'rdns': rdns,
                               'country': g.get('country', ''), 'region': g.get('region', ''),
                               'city': g.get('city', ''), 'isp': g.get('isp', ''),
                               'org': g.get('org', ''), 'asn': g.get('asn', '')})
    return out


def gen_password(length=16, upper=True, lower=True, digits=True, symbols=True, count=1, avoid_ambiguous=False):
    """用 secrets（密码学安全随机）生成密码。"""
    pools = ''
    if lower:
        pools += string.ascii_lowercase
    if upper:
        pools += string.ascii_uppercase
    if digits:
        pools += string.digits
    if symbols:
        pools += '!@#$%^&*()-_=+[]{};:,.?'
    if avoid_ambiguous:
        for ch in 'Il1O0o':
            pools = pools.replace(ch, '')
    if not pools:
        pools = string.ascii_letters + string.digits
    length = max(4, int(length))
    return [''.join(secrets.choice(pools) for _ in range(length)) for _ in range(max(1, count))]


def password_strength(pw):
    pool = ((26 if any(c.islower() for c in pw) else 0) + (26 if any(c.isupper() for c in pw) else 0) +
            (10 if any(c.isdigit() for c in pw) else 0) + (30 if any(not c.isalnum() for c in pw) else 0))
    bits = int(len(pw) * math.log2(pool)) if pool else 0
    label = '弱' if bits < 40 else ('中' if bits < 70 else ('强' if bits < 100 else '极强'))
    return bits, label


def ensure_lang_templates(d):
    """首次运行把内置语言包写到 <数据目录>/lang/，方便用户找到并自行扩充。"""
    ldir = os.path.join(d, 'lang')
    try:
        os.makedirs(ldir, exist_ok=True)
        for code, strings in _BUILTIN_TRANS.items():
            fp = os.path.join(ldir, code + '.json')
            if not os.path.exists(fp):
                with open(fp, 'w', encoding='utf-8') as f:
                    json.dump({'language': code, 'strings': strings}, f, ensure_ascii=False, indent=2)
        tf = os.path.join(ldir, '_template.json')
        if not os.path.exists(tf):
            with open(tf, 'w', encoding='utf-8') as f:
                json.dump({'language': 'xx', 'strings': {k: '' for k in _BUILTIN_TRANS['en']}}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ---- 本机广播/组播监听（用于“监听某 IP 发出的广播消息”，纯标准库，无需 root） ----
# 端口 -> 服务名；这些是局域网里最常见的“会广播/组播”的协议。
_BCAST_PORTS = {
    137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 5353: 'mDNS', 1900: 'SSDP',
    5355: 'LLMNR', 3702: 'WS-Discovery', 67: 'DHCP-s', 68: 'DHCP-c',
    5060: 'SIP', 6771: 'BT-LSD', 1124: 'HPVirtGrp', 10001: 'Ubiquiti',
}
# 需要加入的组播组（否则收不到这些组播）。
_MCAST_GROUPS = {5353: '224.0.0.251', 1900: '239.255.255.250',
                 5355: '224.0.0.252', 3702: '239.255.255.250', 6771: '239.192.152.143'}


def _ascii_preview(data, n=80):
    """把二进制报文转成可读预览：可打印字符原样，其余用 . 代替。"""
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:n])


def open_bcast_sockets():
    """在常见广播/组播端口上开监听套接字（尽力而为，绑不上的自动跳过）。返回 [(sock, port, name)]。"""
    socks = []
    for port, name in _BCAST_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            except OSError:
                pass
            s.bind(('', port))
            grp = _MCAST_GROUPS.get(port)
            if grp:
                try:
                    mreq = struct.pack('4sl', socket.inet_aton(grp), socket.INADDR_ANY)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                except OSError:
                    pass
            s.setblocking(False)
            socks.append((s, port, name))
        except OSError:
            pass
    return socks


def run_cli(argv):
    """命令行模式，便于脚本/流水线集成。子命令: ping/scan/trace/dns/http/tls/quality。"""
    p = argparse.ArgumentParser(prog='net_probe', description='UU889 网络工具（命令行模式）')
    sub = p.add_subparsers(dest='cmd')
    a = sub.add_parser('ping', help='IP段存活扫描')
    a.add_argument('target'); a.add_argument('--timeout', type=int, default=1000)
    a.add_argument('--workers', type=int, default=64); a.add_argument('--json', action='store_true')
    a.add_argument('--smart', action='store_true', help='智能存活(穿透禁Ping)')
    b = sub.add_parser('scan', help='端口扫描(TCP/UDP)')
    b.add_argument('target'); b.add_argument('--ports', default='top')
    b.add_argument('--proto', default='TCP', choices=['TCP', 'UDP'])
    b.add_argument('--timeout', type=float, default=1.0); b.add_argument('--workers', type=int, default=128)
    b.add_argument('--all', action='store_true'); b.add_argument('--json', action='store_true')
    b.add_argument('--fast', action='store_true', help='高速 selectors 引擎')
    b.add_argument('--syn', action='store_true', help='SYN 半开扫描(需root)')
    b.add_argument('--sv', action='store_true', help='服务/版本识别')
    c = sub.add_parser('trace', help='路由追踪(+地理定位)')
    c.add_argument('target'); c.add_argument('--max-hops', type=int, default=30)
    c.add_argument('--geo', action='store_true'); c.add_argument('--json', action='store_true')
    d = sub.add_parser('dns', help='DNS 正/反向解析'); d.add_argument('target'); d.add_argument('--json', action='store_true')
    e = sub.add_parser('http', help='HTTP(S) 检查'); e.add_argument('url'); e.add_argument('--json', action='store_true')
    f = sub.add_parser('tls', help='TLS 证书检查'); f.add_argument('host'); f.add_argument('--port', type=int, default=443); f.add_argument('--json', action='store_true')
    q = sub.add_parser('quality', help='Ping 质量(丢包/抖动)'); q.add_argument('target'); q.add_argument('--count', type=int, default=5); q.add_argument('--json', action='store_true')
    q.add_argument('--watch', action='store_true', help='连续监测(实时 sparkline)'); q.add_argument('--interval', type=int, default=1000)
    mt = sub.add_parser('mtu', help='路径 MTU 探测'); mt.add_argument('host'); mt.add_argument('--json', action='store_true')
    sv = sub.add_parser('serve', help='启动常驻 HTTP JSON API')
    sv.add_argument('--host', default='127.0.0.1'); sv.add_argument('--port', type=int, default=8899)
    sv.add_argument('--token', default=''); sv.add_argument('--allow', action='store_true', help='启用配置里的授权白名单')
    ii = sub.add_parser('ipinfo', help='IP 归属地(域名→多IP/v4+v6/rDNS/ISP)'); ii.add_argument('target'); ii.add_argument('--json', action='store_true')
    gp = sub.add_parser('genpass', help='生成随机密码'); gp.add_argument('--length', type=int, default=16); gp.add_argument('--count', type=int, default=5)
    gp.add_argument('--no-symbols', action='store_true'); gp.add_argument('--avoid-ambiguous', action='store_true'); gp.add_argument('--json', action='store_true')
    ap = sub.add_parser('arp', help='本地 ARP 邻居表'); ap.add_argument('--json', action='store_true')
    gi = sub.add_parser('genicon', help='生成 U 图标 uu889.ico（打包 exe 用）'); gi.add_argument('--out', default='uu889.ico')
    gd = sub.add_parser('geodl', help='下载离线地理库(DB-IP City Lite)到本地'); gd.add_argument('--out', default='')
    args = p.parse_args(argv)
    if not args.cmd:
        p.print_help()
        return 1

    def dump(obj):
        print(json.dumps(obj, ensure_ascii=False, indent=2))

    if args.cmd == 'ping':
        targets = expand_targets(args.target)
        probe = (lambda ip: smart_alive(ip, args.timeout)) if args.smart else (lambda ip: ping_host(ip, args.timeout))
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            res = list(ex.map(probe, targets))
        if args.json:
            dump(res)
        else:
            for r in res:
                if r['alive']:
                    print('%-24s alive  rtt=%sms ttl=%s' % (r['ip'], r['rtt_ms'], r['ttl']))
            print('# %d/%d alive' % (sum(1 for r in res if r['alive']), len(res)))
        return 0
    if args.cmd == 'scan':
        targets = expand_targets(args.target)
        ports = parse_ports(args.ports)
        rows = []
        if args.proto == 'TCP' and (args.fast or args.syn):
            if args.syn:
                try:
                    rows = syn_scan(targets, ports, timeout=args.timeout)
                except Exception as ex:
                    print('# SYN 不可用(%s)，回退高速扫描' % ex, file=sys.stderr)
                    rows = fast_scan(targets, ports, timeout=args.timeout)
            else:
                rows = fast_scan(targets, ports, timeout=args.timeout)
        else:
            tasks = [(ip, pt) for ip in targets for pt in ports]
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
                for r in ex.map(lambda t: scan_port(t[0], t[1], args.proto, args.timeout), tasks):
                    if args.all or is_open_like(r['state'], r['proto']):
                        rows.append(r)
        if args.sv:
            for r in rows:
                if r['proto'] == 'TCP' and r['state'].startswith('open'):
                    pv = probe_service(r['ip'], r['port'])
                    r['product'], r['version'], r['banner'] = pv['product'], pv['version'], pv['banner']
        if args.json:
            dump(rows)
        else:
            for r in rows:
                extra = ('  ' + (r.get('product', '') + ' ' + r.get('version', '')).strip()) if r.get('product') else ''
                lvl, reason = risk_note(r['port']) if is_open_like(r['state'], r['proto']) else ('', '')
                if lvl:
                    extra += '  [%s危:%s]' % (lvl, reason)
                print('%-24s %5d/%s  %-12s %s%s' % (r['ip'], r['port'], r['proto'], r['state'], r['service'], extra))
            print('# %d open' % sum(1 for r in rows if is_open_like(r['state'], r['proto'])))
        return 0
    if args.cmd == 'trace':
        hops = []

        def oh(h):
            if args.geo and h.get('ip'):
                h['geo'] = geolocate(h['ip'])
            hops.append(h)
            if not args.json:
                g = h.get('geo') or {}
                loc = ' '.join(x for x in (g.get('country', ''), g.get('city', '')) if x)
                print('%2s  %-24s %8s ms  %s' % (h['hop'], h.get('ip') or '*',
                      h.get('rtt_ms') if h.get('rtt_ms') is not None else '-', loc))
        try:
            run_traceroute(args.target, args.max_hops, on_hop=oh)
        except FileNotFoundError as ex:
            print('错误: %s' % ex)
            return 2
        if args.json:
            dump(hops)
        return 0
    if args.cmd == 'dns':
        r = dns_lookup(args.target)
        if args.json:
            dump(r)
        else:
            print('forward: %s' % (', '.join(r['forward']) or '-'))
            print('reverse: %s' % (r['reverse'] or '-'))
            if r['error']:
                print('note: %s' % r['error'])
        return 0
    if args.cmd == 'http':
        r = http_check(args.url)
        if args.json:
            dump(r)
        else:
            extra = ''
            if r.get('tls'):
                extra = '  TLS=%s(剩%s天)' % (r['tls'].get('version'), r['tls'].get('days_left'))
            print('status=%s  time=%sms  redirects=%s  server=%s%s%s' % (
                r['status'], r['elapsed_ms'], r['redirects'], r['server'] or '-', extra,
                ('  err=' + r['error']) if r['error'] else ''))
        return 0
    if args.cmd == 'tls':
        r = tls_check(args.host, args.port)
        if args.json:
            dump(r)
        else:
            if r['ok']:
                print('subject=%s  issuer=%s  剩余=%s天  版本=%s' % (
                    r['subject'], r['issuer'], r['days_left'], r['version']))
            else:
                print('失败: %s' % r['error'])
        return 0
    if args.cmd == 'quality':
        if args.watch:
            ip = resolve_host(args.target) or args.target
            data = []
            try:
                while True:
                    rr = ping_host(ip, 1000)
                    data.append(rr['rtt_ms'] if rr['alive'] else None)
                    data[:] = data[-60:]
                    st = qmon_stats(data)
                    cur = ('%.1f' % data[-1]) if data[-1] is not None else '✗'
                    sys.stdout.write('\r%s  当前%sms 丢包%s%% avg%s 抖动%s    ' % (
                        sparkline(data), cur, st['loss_pct'], st['avg'], st['jitter']))
                    sys.stdout.flush()
                    time.sleep(max(0.2, args.interval / 1000.0))
            except KeyboardInterrupt:
                print()
                return 0
        r = ping_quality(args.target, args.count)
        if args.json:
            dump(r)
        else:
            print('丢包=%s%%  avg=%sms  jitter=%sms  (%d/%d)' % (
                r['loss_pct'], r['avg'], r['jitter'], r['recv'], r['sent']))
        return 0
    if args.cmd == 'mtu':
        r = discover_mtu(args.host)
        if args.json:
            dump(r)
        else:
            print('MTU=%s  (%s)%s' % (r['mtu'], r['ip'], ('  ' + r['note']) if r['note'] else ''))
        return 0
    if args.cmd == 'serve':
        cfg = load_config(os.path.join(data_dir(), 'netprobe_config.json'))
        allow = cfg.get('allowlist', []) if args.allow else None
        set_geo_config(cfg.get('geo', {}).get('mode', 'auto'), cfg.get('geo', {}).get('db', ''))
        srv = run_server(args.host, args.port, args.token, allow,
                         os.path.join(data_dir(), 'netprobe_audit.log'))
        print('UU889 API: http://%s:%d/  端点: health|ping|scan|dns|http|tls|quality  (Ctrl+C 停止)'
              % (args.host, args.port))
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            srv.shutdown()
        return 0
    if args.cmd == 'ipinfo':
        r = ip_info(args.target)
        if args.json:
            dump(r)
        else:
            if r['error']:
                print('错误:', r['error'])
            for rec in r['records']:
                print('%-40s %-5s  %s' % (rec['ip'], rec['family'], rec['rdns'] or '-'))
                print('    %s %s %s ｜ %s ｜ %s' % (rec['country'], rec['region'], rec['city'],
                      rec['isp'] or rec['org'] or '-', rec['asn'] or '-'))
        return 0
    if args.cmd == 'genpass':
        pws = gen_password(args.length, symbols=not args.no_symbols,
                           avoid_ambiguous=args.avoid_ambiguous, count=args.count)
        if args.json:
            dump(pws)
        else:
            for p in pws:
                print(p)
        return 0
    if args.cmd == 'arp':
        rows = arp_table()
        if args.json:
            dump(rows)
        else:
            for r in rows:
                print('%-18s %-18s %s' % (r['ip'], r['mac'], r['vendor'] or ''))
            print('# %d 个邻居' % len(rows))
        return 0
    if args.cmd == 'genicon':
        make_ico(args.out)
        print('已生成 U 图标：%s（可用于 PyInstaller --icon）' % os.path.abspath(args.out))
        return 0
    if args.cmd == 'geodl':
        out = args.out or default_geodb_path(data_dir())

        def _pg(done, total, tag):
            pct = (done * 100 // total) if total else 0
            sys.stdout.write('\r下载 %s：%d%% (%d MB)   ' % (tag, pct, done // 1048576))
            sys.stdout.flush()
        try:
            path = download_geodb(out, progress=_pg)
            print('\n离线地理库已保存：%s' % os.path.abspath(path))
            return 0
        except Exception as e:
            print('\n下载失败：%s' % e)
            return 2
    return 1


# ================================================================== #
#  界面层
# ================================================================== #
# ===================== 网络诊断增强 + 加解密编码 + 生活工具 引擎 =====================
_DNS_TYPES = {'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15, 'TXT': 16, 'AAAA': 28}
_DNS_SERVERS = ['223.5.5.5', '119.29.29.29', '8.8.8.8', '1.1.1.1']


def _dns_encode_name(name):
    out = b''
    for part in name.rstrip('.').split('.'):
        if not part:
            continue
        try:
            b = part.encode('idna')
        except Exception:
            b = part.encode('ascii', 'ignore')
        out += bytes([len(b)]) + b
    return out + b'\x00'


def _dns_read_name(data, off):
    labels = []
    jumped = False
    start = off
    end = off
    hops = 0
    while True:
        if off >= len(data):
            break
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack('>H', data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off = ptr
            jumped = True
            hops += 1
            if hops > 20:
                break
            continue
        off += 1
        if ln == 0:
            break
        labels.append(data[off:off + ln].decode('ascii', 'replace'))
        off += ln
    if not jumped:
        end = off
    return '.'.join(labels), end


def _dns_ask(name, qtype, server, timeout=4):
    tid = random.randint(0, 65535)
    header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    q = _dns_encode_name(name) + struct.pack('>HH', _DNS_TYPES[qtype], 1)
    pkt = header + q
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    return data


def _dns_parse(data, want):
    qd = struct.unpack('>H', data[4:6])[0]
    an = struct.unpack('>H', data[6:8])[0]
    off = 12
    for _ in range(qd):
        _, off = _dns_read_name(data, off)
        off += 4
    recs = []
    for _ in range(an):
        _, off = _dns_read_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        if rtype == _DNS_TYPES['A'] and rdlen == 4:
            recs.append(('A', socket.inet_ntoa(rdata)))
        elif rtype == _DNS_TYPES['AAAA'] and rdlen == 16:
            recs.append(('AAAA', socket.inet_ntop(socket.AF_INET6, rdata)))
        elif rtype in (_DNS_TYPES['CNAME'], _DNS_TYPES['NS'], _DNS_TYPES['PTR']):
            nm, _ = _dns_read_name(data, off)
            recs.append((({5: 'CNAME', 2: 'NS', 12: 'PTR'})[rtype], nm))
        elif rtype == _DNS_TYPES['MX']:
            pref = struct.unpack('>H', rdata[:2])[0]
            nm, _ = _dns_read_name(data, off + 2)
            recs.append(('MX', '%d %s' % (pref, nm)))
        elif rtype == _DNS_TYPES['TXT']:
            i = 0
            parts = []
            while i < len(rdata):
                l = rdata[i]
                parts.append(rdata[i + 1:i + 1 + l].decode('utf-8', 'replace'))
                i += 1 + l
            recs.append(('TXT', ''.join(parts)))
        elif rtype == _DNS_TYPES['SOA']:
            mname, p = _dns_read_name(data, off)
            recs.append(('SOA', mname))
        off += rdlen
    return [r for r in recs if r[0] == want] if want else recs


def dns_query(name, qtypes=None, timeout=4):
    if qtypes is None:
        qtypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
    try:
        nm = name.strip().encode('idna').decode('ascii')
    except Exception:
        nm = name.strip()
    out = {'name': name, 'records': {}, 'error': ''}
    ok_any = False
    for qt in qtypes:
        got = []
        for srv in _DNS_SERVERS:
            try:
                got = _dns_parse(_dns_ask(nm, qt, srv, timeout), qt)
                ok_any = True
                break
            except Exception:
                continue
        out['records'][qt] = got
    if not ok_any:
        out['error'] = '所有 DNS 服务器均无响应（可能无网络）'
    return out


_WHOIS_IANA = 'whois.iana.org'


def _whois_ask(server, query, timeout=8):
    s = socket.create_connection((server, 43), timeout=timeout)
    try:
        s.sendall((query + '\r\n').encode('ascii', 'ignore'))
        buf = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 200000:
                break
    finally:
        s.close()
    return buf.decode('utf-8', 'replace')


def whois_query(target, timeout=8):
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        q = target
    except ValueError:
        try:
            q = target.encode('idna').decode('ascii')
        except Exception:
            q = target
    try:
        first = _whois_ask(_WHOIS_IANA, q, timeout)
    except Exception as e:
        return {'target': target, 'server': _WHOIS_IANA, 'text': '', 'error': '连接 whois.iana.org 失败: %s' % e}
    refer = ''
    for line in first.splitlines():
        low = line.strip().lower()
        if low.startswith('refer:') or low.startswith('whois:'):
            refer = line.split(':', 1)[1].strip()
    if refer and refer != _WHOIS_IANA:
        try:
            second = _whois_ask(refer, q, timeout)
            return {'target': target, 'server': refer, 'text': second.strip(), 'via': _WHOIS_IANA}
        except Exception as e:
            return {'target': target, 'server': refer, 'text': first.strip(),
                    'error': '向 %s 查询失败: %s（下方为 IANA 概要）' % (refer, e)}
    return {'target': target, 'server': _WHOIS_IANA, 'text': first.strip()}


def cidr_info(text):
    net = ipaddress.ip_network(text.strip(), strict=False)
    total = net.num_addresses
    v4 = net.version == 4
    if v4 and net.prefixlen <= 30:
        usable = total - 2
        host_first, host_last = str(net[1]), str(net[-2])
    else:
        usable = total
        host_first, host_last = str(net[0]), str(net[-1])
    return {
        '输入': text.strip(), '版本': 'IPv%d' % net.version, '前缀长度': '/%d' % net.prefixlen,
        '网络地址': str(net.network_address),
        '广播地址': str(net.broadcast_address) if v4 else '（IPv6 无广播）',
        '子网掩码': str(net.netmask), '通配符掩码': str(net.hostmask),
        '地址总数': str(total), '可用主机数': str(max(usable, 0)),
        '主机范围': '%s ~ %s' % (host_first, host_last),
        '是否私有': '是' if net.is_private else '否',
    }


# ---------------- 加解密 / 编码 ----------------
_MORSE = {'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.',
          'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.',
          'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-',
          'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '0': '-----',
          '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....',
          '7': '--...', '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..'}
_MORSE_R = {v: k for k, v in _MORSE.items()}


def _rot13(t):
    out = []
    for c in t:
        o = ord(c)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + 13) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + 13) % 26 + 97))
        else:
            out.append(c)
    return ''.join(out)


def codec_run(tool, text, mode='enc'):
    t = text
    if tool == 'base64':
        return base64.b64encode(t.encode('utf-8')).decode() if mode == 'enc' else base64.b64decode(t.strip() + '=' * (-len(t.strip()) % 4)).decode('utf-8', 'replace')
    if tool == 'base64url':
        return base64.urlsafe_b64encode(t.encode('utf-8')).decode() if mode == 'enc' else base64.urlsafe_b64decode(t.strip() + '=' * (-len(t.strip()) % 4)).decode('utf-8', 'replace')
    if tool == 'url':
        return urllib.parse.quote(t, safe='') if mode == 'enc' else urllib.parse.unquote(t)
    if tool == 'hex':
        return t.encode('utf-8').hex() if mode == 'enc' else bytes.fromhex(''.join(t.split())).decode('utf-8', 'replace')
    if tool == 'html':
        return html.escape(t) if mode == 'enc' else html.unescape(t)
    if tool == 'unicode':
        return t.encode('unicode_escape').decode('latin-1') if mode == 'enc' else t.encode('latin-1', 'ignore').decode('unicode_escape')
    if tool == 'rot13':
        return _rot13(t)
    if tool in ('md5', 'sha1', 'sha256', 'sha512'):
        return hashlib.new(tool, t.encode('utf-8')).hexdigest()
    if tool == 'json':
        obj = json.loads(t)
        return json.dumps(obj, ensure_ascii=False, indent=2) if mode == 'enc' else json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
    if tool == 'ts2date':
        v = float(t.strip())
        if v > 1e12:
            v /= 1000.0
        return datetime.fromtimestamp(v).strftime('%Y-%m-%d %H:%M:%S')
    if tool == 'date2ts':
        return str(int(datetime.strptime(t.strip(), '%Y-%m-%d %H:%M:%S').timestamp()))
    if tool == 'morse':
        if mode == 'enc':
            return ' '.join(_MORSE.get(c.upper(), c) for c in t)
        return ''.join(_MORSE_R.get(tok, ' ' if tok == '' else tok) for tok in t.split(' '))
    return '（未知工具）'


def base_convert(text, from_base, to_base):
    n = int(text.strip(), from_base)
    if to_base == 10:
        return str(n)
    digs = '0123456789abcdefghijklmnopqrstuvwxyz'
    if n == 0:
        return '0'
    neg = n < 0
    n = abs(n)
    out = ''
    while n:
        out = digs[n % to_base] + out
        n //= to_base
    return ('-' if neg else '') + out
_U_LEN = {'m': 1.0, 'km': 1000.0, 'dm': 0.1, 'cm': 0.01, 'mm': 0.001, 'um': 1e-6, 'nm': 1e-9,
          'inch': 0.0254, 'in': 0.0254, 'ft': 0.3048, 'yd': 0.9144, 'mile': 1609.344,
          'mil': 2.54e-5, 'hand': 0.1016, 'rod': 5.0292, 'chain': 20.1168,
          'furlong': 201.168, 'fathom': 1.8288, 'league': 4828.032, 'nmi': 1852.0,
          '里': 500.0, '尺': 1.0 / 3, '寸': 1.0 / 30, '海里': 1852.0}
_U_AREA = {'m2': 1.0, 'km2': 1e6, 'cm2': 1e-4, 'mm2': 1e-6, 'ha': 1e4, '公顷': 1e4,
           '亩': 2000.0 / 3, 'acre': 4046.856, 'ft2': 0.092903}
_U_VOL = {'m3': 1.0, 'l': 1e-3, 'ml': 1e-6, 'cm3': 1e-6, '升': 1e-3, '毫升': 1e-6,
          'gal': 3.785412e-3, '加仑': 3.785412e-3}
_U_MASS = {'kg': 1.0, 'g': 1e-3, 'mg': 1e-6, 't': 1000.0, '吨': 1000.0, 'lb': 0.4535924,
           '磅': 0.4535924, 'oz': 0.02834952, '斤': 0.5, '两': 0.05}
_U_SPEED = {'m/s': 1.0, 'km/h': 1 / 3.6, 'mph': 0.44704, 'kn': 0.5144444, '节': 0.5144444}
_U_TIME = {'s': 1.0, 'ms': 1e-3, 'min': 60.0, 'h': 3600.0, 'day': 86400.0, 'd': 86400.0,
           'week': 604800.0, '周': 604800.0}
_U_POWER = {'w': 1.0, 'kw': 1000.0, 'mw': 1e6, 'hp': 745.6999, '马力': 735.49875, 'ps': 735.49875}
_U_PRESS = {'pa': 1.0, 'kpa': 1000.0, 'mpa': 1e6, 'bar': 1e5, 'atm': 101325.0, 'mmhg': 133.322, 'psi': 6894.757}
_U_ENERGY = {'j': 1.0, 'kj': 1000.0, 'cal': 4.184, 'kcal': 4184.0, 'kwh': 3.6e6, 'wh': 3600.0}
_U_DENSITY = {'kg/m3': 1.0, 'g/cm3': 1000.0, 'g/ml': 1000.0, 'kg/l': 1000.0}


def _uconv(table, val, fu, tu, name):
    fu = fu.strip().lower().replace('²', '2').replace('³', '3')
    tu = tu.strip().lower().replace('²', '2').replace('³', '3')
    tl = {k.lower(): v for k, v in table.items()}
    if fu not in tl or tu not in tl:
        raise ValueError('%s单位仅支持：%s' % (name, ' / '.join(table.keys())))
    return float(val) * tl[fu] / tl[tu]


def _u_str(table, name, vals):
    v, fu, tu = float(vals[0]), vals[1], vals[2]
    r = _uconv(table, v, fu, tu, name)
    return '%g %s = %.6g %s' % (v, fu, r, tu)


def _temp(vals):
    v = float(vals[0]); fu = vals[1].strip().lower(); tu = vals[2].strip().lower()
    if fu in ('c', '℃', '摄氏'): c = v
    elif fu in ('f', '℉', '华氏'): c = (v - 32) * 5 / 9
    elif fu in ('k', '开', '开尔文'): c = v - 273.15
    else: raise ValueError('温度单位: c / f / k')
    if tu in ('c', '℃', '摄氏'): r = c
    elif tu in ('f', '℉', '华氏'): r = c * 9 / 5 + 32
    elif tu in ('k', '开', '开尔文'): r = c + 273.15
    else: raise ValueError('温度单位: c / f / k')
    return '%g %s = %.4g %s' % (v, fu, r, tu)


def _geo(shape, vals):
    import math
    f = [float(x) for x in vals]
    if shape == 'cube':
        a = f[0]; return '体积=%.6g，表面积=%.6g' % (a**3, 6 * a * a)
    if shape == 'cuboid':
        a, b, c = f; return '体积=%.6g，表面积=%.6g' % (a * b * c, 2 * (a * b + b * c + a * c))
    if shape == 'sphere':
        r = f[0]; return '体积=%.6g，表面积=%.6g' % (4 / 3 * math.pi * r**3, 4 * math.pi * r * r)
    if shape == 'cylinder':
        r, h = f; return '体积=%.6g，表面积=%.6g' % (math.pi * r * r * h, 2 * math.pi * r * (r + h))
    if shape == 'cone':
        r, h = f; l = math.hypot(r, h); return '体积=%.6g，表面积=%.6g（母线=%.4g）' % (math.pi * r * r * h / 3, math.pi * r * (r + l), l)
    if shape == 'torus':
        R, r = f; return '体积=%.6g，表面积=%.6g' % (2 * math.pi**2 * R * r * r, 4 * math.pi**2 * R * r)
    if shape == 'trapezoid':
        a, b, h = f; return '面积=%.6g' % ((a + b) * h / 2)
    if shape == 'hexprism':
        a, h = f; base = 3 * math.sqrt(3) / 2 * a * a; return '体积=%.6g，表面积=%.6g' % (base * h, 2 * base + 6 * a * h)
    return '?'


def iit_cn(vals):
    salary = float(vals[0]); ins = float(vals[1] or 0); spec = float(vals[2] or 0)
    taxable = salary - 5000 - ins - spec
    if taxable <= 0:
        return '应纳税所得额=%.2f（≤0，免税）\n税后收入≈%.2f 元' % (taxable, salary - ins)
    brk = [(3000, 0.03, 0), (12000, 0.10, 210), (25000, 0.20, 1410), (35000, 0.25, 2660),
           (55000, 0.30, 4410), (80000, 0.35, 7160), (float('inf'), 0.45, 15160)]
    for cap, rate, ded in brk:
        if taxable <= cap:
            tax = taxable * rate - ded
            break
    return ('应纳税所得额=%.2f 元\n适用税率=%.0f%%，速算扣除=%.0f\n应缴个税≈%.2f 元\n税后收入≈%.2f 元\n'
            '（按月度简易估算；实际为累计预扣，年终可能有差异）' % (taxable, rate * 100, ded, tax, salary - ins - tax))


def loan_calc(vals):
    P = float(vals[0]); ar = float(vals[1]) / 100; n = int(float(vals[2])); method = str(vals[3]).strip()
    r = ar / 12
    if '本金' in method or method == '2':
        first_i = P * r; mp = P / n
        total_i = P * r * (n + 1) / 2
        return ('等额本金：每月本金=%.2f 元\n首月还款=%.2f，末月还款=%.2f\n总利息≈%.2f，总还款≈%.2f 元'
                % (mp, mp + first_i, mp + P / n * 0 + (P - mp * (n - 1)) * r + mp, total_i, P + total_i))
    if r == 0:
        m = P / n
    else:
        m = P * r * (1 + r) ** n / ((1 + r) ** n - 1)
    total = m * n
    return ('等额本息：每月还款=%.2f 元\n总还款=%.2f，总利息=%.2f 元' % (m, total, total - P))


def deposit_calc(vals):
    P = float(vals[0]); ar = float(vals[1]) / 100; y = float(vals[2]); typ = str(vals[3]).strip()
    if '复' in typ or typ == '2':
        amt = P * (1 + ar) ** y
    else:
        amt = P * (1 + ar * y)
    return '到期本息=%.2f 元，利息=%.2f 元' % (amt, amt - P)


def rate_convert(vals):
    r = float(vals[0]); ppy = {'年': 1.0, '月': 12.0, '日': 365.0}
    fu = vals[1].strip(); tu = vals[2].strip()
    if fu not in ppy or tu not in ppy:
        raise ValueError('周期只能是 年/月/日')
    r2 = r * ppy[fu] / ppy[tu]
    return '%g%% (每%s) = %.6g%% (每%s)' % (r, fu, r2, tu)


def date_diff(vals):
    from datetime import datetime as _dt
    d1 = _dt.strptime(vals[0].strip(), '%Y-%m-%d'); d2 = _dt.strptime(vals[1].strip(), '%Y-%m-%d')
    return '相差 %d 天' % abs((d2 - d1).days)


def date_add(vals):
    from datetime import datetime as _dt, timedelta
    d = _dt.strptime(vals[0].strip(), '%Y-%m-%d'); n = int(float(vals[1]))
    r = d + timedelta(days=n)
    wk = '一二三四五六日'[r.weekday()]
    return '%s（星期%s）' % (r.strftime('%Y-%m-%d'), wk)


def rmb_capital(vals):
    amount = round(float(vals[0]) + 1e-9, 2)
    nums = '零壹贰叁肆伍陆柒捌玖'; units = ['', '拾', '佰', '仟']; big = ['', '万', '亿', '兆']
    neg = amount < 0; amount = abs(amount)
    intpart = int(amount); dec = int(round((amount - intpart) * 100)); jiao = dec // 10; fen = dec % 10

    def sec(n):
        res = ''; zero = False
        digs = []
        while n > 0:
            digs.append(n % 10); n //= 10
        for i in range(len(digs) - 1, -1, -1):
            d = digs[i]
            if d == 0:
                zero = True
            else:
                if zero and res:
                    res += '零'
                zero = False
                res += nums[d] + units[i]
        return res
    s = ''
    if intpart > 0:
        segs = []; tmp = intpart
        while tmp > 0:
            segs.append(tmp % 10000); tmp //= 10000
        gap = False
        for i in range(len(segs) - 1, -1, -1):
            seg = segs[i]
            if seg == 0:
                if s:
                    gap = True
                continue
            if s and not s.endswith('零') and (gap or seg < 1000):
                s += '零'
            s += sec(seg) + big[i]
            gap = False
        s += '元'
    if jiao == 0 and fen == 0:
        s = (s or '零元') + '整'
    else:
        if jiao > 0:
            s += nums[jiao] + '角'
        elif intpart > 0 and fen > 0:
            s += '零'
        if fen > 0:
            s += nums[fen] + '分'
    return ('负' + s) if neg else s


def date_capital(vals):
    s = vals[0].strip().replace('/', '-')
    zh = '〇一二三四五六七八九'
    from datetime import datetime as _dt
    d = _dt.strptime(s, '%Y-%m-%d')
    y = ''.join(zh[int(c)] for c in '%04d' % d.year)
    mo = {1: '一', 2: '二', 3: '三', 4: '四', 5: '五', 6: '六', 7: '七', 8: '八', 9: '九', 10: '十', 11: '十一', 12: '十二'}[d.month]
    dd = d.day
    day = ('十' if dd == 10 else (zh[dd] if dd < 10 else ('十' + zh[dd - 10] if dd < 20 else (zh[dd // 10] + '十' + (zh[dd % 10] if dd % 10 else '')))))
    return '%s年%s月%s日' % (y, mo, day)


def zodiac_sign(vals):
    m = int(float(vals[0])); day = int(float(vals[1]))
    cut = {1: (20, '水瓶座', '摩羯座'), 2: (19, '双鱼座', '水瓶座'), 3: (21, '白羊座', '双鱼座'),
           4: (20, '金牛座', '白羊座'), 5: (21, '双子座', '金牛座'), 6: (22, '巨蟹座', '双子座'),
           7: (23, '狮子座', '巨蟹座'), 8: (23, '处女座', '狮子座'), 9: (23, '天秤座', '处女座'),
           10: (24, '天蝎座', '天秤座'), 11: (23, '射手座', '天蝎座'), 12: (22, '摩羯座', '射手座')}
    c, after, before = cut[m]
    return after if day >= c else before


def chinese_zodiac(vals):
    y = int(float(vals[0]))
    a = ['鼠', '牛', '虎', '兔', '龙', '蛇', '马', '羊', '猴', '鸡', '狗', '猪']
    return a[(y - 4) % 12] + '年'


_BLOOD = {'A': ['A', 'O'], 'B': ['B', 'O'], 'O': ['O'], 'AB': ['A', 'B']}


def blood_inherit(vals):
    f = vals[0].strip().upper(); m = vals[1].strip().upper()
    if f not in _BLOOD or m not in _BLOOD:
        raise ValueError('血型只能是 A / B / O / AB')

    def ph(x, y):
        s = {x, y}
        if s == {'O'}: return 'O'
        if 'A' in s and 'B' in s: return 'AB'
        return 'A' if 'A' in s else 'B'
    poss = sorted({ph(a, b) for a in _BLOOD[f] for b in _BLOOD[m]})
    imp = sorted(set(['A', 'B', 'O', 'AB']) - set(poss))
    return '孩子可能血型：%s\n不可能：%s' % ('、'.join(poss), '、'.join(imp) or '无')


_PAPER = {'A0': '841×1189', 'A1': '594×841', 'A2': '420×594', 'A3': '297×420', 'A4': '210×297',
          'A5': '148×210', 'A6': '105×148', 'A7': '74×105', 'A8': '52×74',
          'B0': '1000×1414', 'B1': '707×1000', 'B2': '500×707', 'B3': '353×500', 'B4': '250×353',
          'B5': '176×250', 'B6': '125×176'}


def paper_size(vals):
    k = vals[0].strip().upper()
    if k not in _PAPER:
        raise ValueError('支持：%s' % ' '.join(_PAPER.keys()))
    return '%s = %s mm' % (k, _PAPER[k])


_TZ = {'北京': 8, '上海': 8, '香港': 8, '台北': 8, '东京': 9, '首尔': 9, '新加坡': 8, '曼谷': 7,
       '新德里': 5.5, '迪拜': 4, '莫斯科': 3, '柏林': 1, '巴黎': 1, '伦敦': 0, '纽约': -5,
       '芝加哥': -6, '洛杉矶': -8, '悉尼': 11}


def world_time(vals):
    from datetime import datetime as _dt, timedelta
    c = vals[0].strip()
    if c not in _TZ:
        raise ValueError('支持城市：%s' % ' '.join(_TZ.keys()))
    t = _dt.utcnow() + timedelta(hours=_TZ[c])
    return '%s 当前时间：%s (UTC%+g，未计夏令时)' % (c, t.strftime('%Y-%m-%d %H:%M:%S'), _TZ[c])


def case_convert(vals):
    t = vals[0]; m = str(vals[1]).strip()
    if m in ('1', '大写', 'upper'): return t.upper()
    if m in ('2', '小写', 'lower'): return t.lower()
    if m in ('3', '首字母', 'title'): return t.title()
    if m in ('4', '切换', 'swap'): return t.swapcase()
    return t.upper()


# ---------------- 工具注册表（UI 遍历用） ----------------
CODEC_TOOLS = [
    ('Base64 编解码', 'base64', True), ('Base64URL', 'base64url', True),
    ('URL 编解码', 'url', True), ('Hex 十六进制', 'hex', True),
    ('HTML 实体', 'html', True), ('Unicode 转义', 'unicode', True),
    ('JSON 格式化/压缩', 'json', True), ('摩尔斯电码', 'morse', True),
    ('ROT13', 'rot13', False), ('MD5', 'md5', False), ('SHA1', 'sha1', False),
    ('SHA256', 'sha256', False), ('SHA512', 'sha512', False),
    ('时间戳→日期', 'ts2date', False), ('日期→时间戳', 'date2ts', False),
]

_KIN_ALIAS = {
    '爸': '父', '爸爸': '父', '父亲': '父', '老爸': '父', '爹': '父', '父': '父',
    '妈': '母', '妈妈': '母', '母亲': '母', '老妈': '母', '娘': '母', '母': '母',
    '老公': '夫', '丈夫': '夫', '先生': '夫', '夫': '夫',
    '老婆': '妻', '妻子': '妻', '太太': '妻', '妻': '妻',
    '儿子': '子', '儿': '子', '子': '子',
    '女儿': '女', '闺女': '女', '女': '女',
    '哥哥': '兄', '哥': '兄', '大哥': '兄', '兄': '兄', '兄长': '兄',
    '弟弟': '弟', '弟': '弟', '小弟': '弟',
    '姐姐': '姐', '姐': '姐', '姊': '姐',
    '妹妹': '妹', '妹': '妹',
}
_KIN_EXPAND = {
    '爷爷': ['父', '父'], '爷': ['父', '父'], '祖父': ['父', '父'],
    '奶奶': ['父', '母'], '祖母': ['父', '母'],
    '外公': ['母', '父'], '姥爷': ['母', '父'], '外祖父': ['母', '父'],
    '外婆': ['母', '母'], '姥姥': ['母', '母'], '外祖母': ['母', '母'],
    '伯伯': ['父', '兄'], '伯父': ['父', '兄'], '大伯': ['父', '兄'],
    '叔叔': ['父', '弟'], '叔父': ['父', '弟'], '叔': ['父', '弟'],
    '姑姑': ['父', '姐'], '姑妈': ['父', '姐'], '姑': ['父', '姐'],
    '舅舅': ['母', '兄'], '舅父': ['母', '兄'], '舅': ['母', '兄'],
    '姨妈': ['母', '姐'], '阿姨': ['母', '姐'], '姨': ['母', '姐'], '姨母': ['母', '姐'],
    '孙子': ['子', '子'], '孙女': ['子', '女'], '外孙': ['女', '子'], '外孙女': ['女', '女'],
    '侄子': ['兄', '子'], '侄女': ['兄', '女'], '外甥': ['姐', '子'], '外甥女': ['姐', '女'],
    '嫂子': ['兄', '妻'], '嫂嫂': ['兄', '妻'], '弟媳': ['弟', '妻'], '弟妹': ['弟', '妻'],
    '姐夫': ['姐', '夫'], '妹夫': ['妹', '夫'],
    '岳父': ['妻', '父'], '岳母': ['妻', '母'], '公公': ['夫', '父'], '婆婆': ['夫', '母'],
    '女婿': ['女', '夫'], '儿媳': ['子', '妻'], '媳妇': ['子', '妻'],
}
_KIN_MAP = {
    '父': '爸爸', '母': '妈妈', '夫': '丈夫', '妻': '妻子', '子': '儿子', '女': '女儿',
    '兄': '哥哥', '弟': '弟弟', '姐': '姐姐', '妹': '妹妹',
    '父父': '爷爷', '父母': '奶奶', '母父': '外公(姥爷)', '母母': '外婆(姥姥)',
    '父父父': '曾祖父', '父父母': '曾祖母', '母母母': '外曾祖母', '母母父': '外曾祖父',
    '子': '儿子', '子子': '孙子', '子女': '孙女', '女子': '外孙', '女女': '外孙女',
    '子子子': '曾孙', '子子女': '曾孙女',
    '父兄': '伯父(伯伯)', '父弟': '叔叔', '父姐': '姑姑', '父妹': '姑姑',
    '母兄': '舅舅', '母弟': '舅舅', '母姐': '姨妈', '母妹': '姨妈',
    '父兄妻': '伯母', '父弟妻': '婶婶', '父姐夫': '姑父', '父妹夫': '姑父',
    '母兄妻': '舅妈', '母弟妻': '舅妈', '母姐夫': '姨父', '母妹夫': '姨父',
    '兄子': '侄子', '弟子': '侄子', '兄女': '侄女', '弟女': '侄女',
    '姐子': '外甥', '妹子': '外甥', '姐女': '外甥女', '妹女': '外甥女',
    '父兄子': '堂兄弟', '父弟子': '堂兄弟', '父兄女': '堂姐妹', '父弟女': '堂姐妹',
    '父姐子': '表兄弟', '父姐女': '表姐妹', '父妹子': '表兄弟', '父妹女': '表姐妹',
    '母兄子': '表兄弟', '母兄女': '表姐妹', '母弟子': '表兄弟', '母弟女': '表姐妹',
    '母姐子': '表兄弟', '母姐女': '表姐妹', '母妹子': '表兄弟', '母妹女': '表姐妹',
    '妻父': '岳父', '妻母': '岳母', '夫父': '公公', '夫母': '婆婆',
    '女夫': '女婿', '子妻': '儿媳', '兄妻': '嫂子', '弟妻': '弟媳(弟妹)', '姐夫': '姐夫', '妹夫': '妹夫',
    '夫兄': '大伯子', '夫弟': '小叔子', '夫姐': '大姑子', '夫妹': '小姑子',
    '妻兄': '大舅子', '妻弟': '小舅子', '妻姐': '大姨子', '妻妹': '小姨子',
    '兄子妻': '侄媳', '子子妻': '孙媳', '女夫父': '亲家公', '子妻父': '亲家公',
}


def _kin_tokenize(s):
    s = s.strip()
    keys = sorted(set(list(_KIN_ALIAS) + list(_KIN_EXPAND)), key=len, reverse=True)
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch in '的· ，,、和':
            i += 1
            continue
        if ch in ('我', '自'):
            i += 1
            continue
        matched = None
        for k in keys:
            if s.startswith(k, i):
                matched = k
                break
        if not matched:
            i += 1
            continue
        if matched in _KIN_EXPAND:
            out.extend(_KIN_EXPAND[matched])
        else:
            out.append(_KIN_ALIAS[matched])
        i += len(matched)
    return out


def kinship(vals):
    s = vals[0].strip()
    prim = _kin_tokenize(s)
    if not prim:
        raise ValueError('请输入关系链，如：爸爸的哥哥的儿子')
    key = ''.join(prim)
    if key in _KIN_MAP:
        return '%s → 【%s】' % (s, _KIN_MAP[key])
    if all(x in ('父', '母') for x in prim):
        n = len(prim); side = '外' if prim[0] == '母' else ''
        g = '祖父' if prim[-1] == '父' else '祖母'
        pre = {3: '曾', 4: '高', 5: '天', 6: '烈', 7: '太', 8: '远', 9: '鼻'}.get(n, '第%d代' % n)
        return '%s → 【%s%s%s】(第%d代直系长辈)' % (s, side, pre, g, n)
    if all(x in ('子', '女') for x in prim):
        n = len(prim); g = '孙' if prim[-1] == '子' else '孙女'
        pre = {3: '曾', 4: '玄', 5: '来', 6: '晜', 7: '仍', 8: '云', 9: '耳'}.get(n, '第%d代' % n)
        return '%s → 【%s%s】(第%d代直系晚辈)' % (s, pre, g, n)
    return '%s → （旁系较复杂，暂无法精确命名，可尝试更常见的关系）' % s

LIFE_TOOLS = [
    {'name': '长度换算(公制/英制)', 'fields': [('数值', '1'), ('从单位 公制:m/km/cm/mm 英制:inch/ft/yd/mile', 'inch'), ('到单位', 'cm')], 'run': lambda v: _u_str(_U_LEN, '长度', v)},
    {'name': '面积换算', 'fields': [('数值', '1'), ('从单位', '亩'), ('到单位', 'm2')], 'run': lambda v: _u_str(_U_AREA, '面积', v)},
    {'name': '体积/容积换算', 'fields': [('数值', '1'), ('从单位', 'l'), ('到单位', 'ml')], 'run': lambda v: _u_str(_U_VOL, '体积', v)},
    {'name': '质量/重量换算', 'fields': [('数值', '1'), ('从单位', 'kg'), ('到单位', '斤')], 'run': lambda v: _u_str(_U_MASS, '质量', v)},
    {'name': '温度换算', 'fields': [('数值', '100'), ('从(c/f/k)', 'c'), ('到(c/f/k)', 'f')], 'run': _temp},
    {'name': '速度换算', 'fields': [('数值', '100'), ('从单位', 'km/h'), ('到单位', 'm/s')], 'run': lambda v: _u_str(_U_SPEED, '速度', v)},
    {'name': '时间换算', 'fields': [('数值', '1'), ('从单位', 'h'), ('到单位', 's')], 'run': lambda v: _u_str(_U_TIME, '时间', v)},
    {'name': '功率换算', 'fields': [('数值', '1'), ('从单位', 'hp'), ('到单位', 'w')], 'run': lambda v: _u_str(_U_POWER, '功率', v)},
    {'name': '压力换算', 'fields': [('数值', '1'), ('从单位', 'atm'), ('到单位', 'kpa')], 'run': lambda v: _u_str(_U_PRESS, '压力', v)},
    {'name': '热量/能量换算', 'fields': [('数值', '1'), ('从单位', 'kcal'), ('到单位', 'kj')], 'run': lambda v: _u_str(_U_ENERGY, '能量', v)},
    {'name': '密度换算', 'fields': [('数值', '1'), ('从单位', 'g/cm3'), ('到单位', 'kg/m3')], 'run': lambda v: _u_str(_U_DENSITY, '密度', v)},
    {'name': '正方体', 'fields': [('边长 a', '2')], 'run': lambda v: _geo('cube', v)},
    {'name': '长方体', 'fields': [('长', '2'), ('宽', '3'), ('高', '4')], 'run': lambda v: _geo('cuboid', v)},
    {'name': '球体', 'fields': [('半径 r', '5')], 'run': lambda v: _geo('sphere', v)},
    {'name': '圆柱体', 'fields': [('半径 r', '3'), ('高 h', '10')], 'run': lambda v: _geo('cylinder', v)},
    {'name': '圆锥体', 'fields': [('半径 r', '3'), ('高 h', '10')], 'run': lambda v: _geo('cone', v)},
    {'name': '圆环体', 'fields': [('大半径 R', '5'), ('小半径 r', '2')], 'run': lambda v: _geo('torus', v)},
    {'name': '梯形(面积)', 'fields': [('上底 a', '2'), ('下底 b', '4'), ('高 h', '3')], 'run': lambda v: _geo('trapezoid', v)},
    {'name': '正六棱柱', 'fields': [('边长 a', '2'), ('高 h', '5')], 'run': lambda v: _geo('hexprism', v)},
    {'name': '个人所得税(月估算)', 'fields': [('税前工资', '20000'), ('五险一金', '0'), ('专项附加扣除', '0')], 'run': iit_cn},
    {'name': '贷款计算器', 'fields': [('贷款本金(元)', '1000000'), ('年利率(%)', '4.9'), ('期数(月)', '360'), ('方式(等额本息/等额本金)', '等额本息')], 'run': loan_calc},
    {'name': '存款利息', 'fields': [('本金(元)', '10000'), ('年利率(%)', '2'), ('存期(年)', '3'), ('类型(单利/复利)', '复利')], 'run': deposit_calc},
    {'name': '利率换算', 'fields': [('利率值(%)', '0.5'), ('从(年/月/日)', '月'), ('到(年/月/日)', '年')], 'run': rate_convert},
    {'name': '日期间隔', 'fields': [('日期1(YYYY-MM-DD)', '2024-01-01'), ('日期2', '2024-12-31')], 'run': date_diff},
    {'name': '日期推算', 'fields': [('起始日期', '2024-01-01'), ('加减天数', '100')], 'run': date_add},
    {'name': '世界时间', 'fields': [('城市', '东京')], 'run': world_time},
    {'name': '数字→人民币大写', 'fields': [('金额', '1234.56')], 'run': rmb_capital},
    {'name': '日期→大写', 'fields': [('日期(YYYY-MM-DD)', '2024-01-05')], 'run': date_capital},
    {'name': '英文大小写转换', 'fields': [('文本', 'Hello World'), ('模式(大写/小写/首字母/切换)', '大写')], 'run': case_convert},
    {'name': '星座查询', 'fields': [('月', '3'), ('日', '25')], 'run': zodiac_sign},
    {'name': '生肖查询', 'fields': [('年份', '2020')], 'run': chinese_zodiac},
    {'name': '血型遗传', 'fields': [('父方(A/B/O/AB)', 'A'), ('母方(A/B/O/AB)', 'B')], 'run': blood_inherit},
    {'name': '纸张尺寸', 'fields': [('规格(A4/B5...)', 'A4')], 'run': paper_size},
    {'name': '亲戚称谓计算', 'fields': [('关系链(如 爸爸的哥哥的儿子)', '爸爸的哥哥的儿子')], 'run': kinship},
]


class UU889App:
    def __init__(self, root):
        self.root = root
        self.root.title('UU889  网络工具')
        self.root.geometry('1220x800')
        self.root.minsize(1024, 640)
        try:
            self._icon_img = tk.PhotoImage(data=base64.b64encode(_icon_png(64)).decode('ascii'))
            self.root.iconphoto(True, self._icon_img)
        except Exception:
            pass

        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.scanning = False
        self.start_buttons = []
        self.trace_results = []            # 最近一次路由追踪结果（供世界地图）
        self.monitoring = False
        self.monitor_stop = threading.Event()
        self.qmon_running = False
        self.qmon_stop = threading.Event()
        self.qmon_data = []
        self.qmon_max = 180
        self.data_dir = data_dir()
        try:
            make_ico(os.path.join(self.data_dir, 'uu889.ico'))
        except Exception:
            pass
        self.cfg_path = os.path.join(self.data_dir, 'netprobe_config.json')
        self.db_path = os.path.join(self.data_dir, 'netprobe.db')
        self.alert_cfg = load_config(self.cfg_path)
        self.audit_path = os.path.join(self.data_dir, 'netprobe_audit.log')
        set_geo_config(self.alert_cfg.get('geo', {}).get('mode', 'auto'),
                       self.alert_cfg.get('geo', {}).get('db', ''))
        ensure_lang_templates(self.data_dir)
        load_langpacks(self.data_dir)
        set_lang(self.alert_cfg.get('lang', 'zh'))

        self._build_style()
        top_bar = ttk.Frame(root)
        top_bar.pack(fill='x', padx=8, pady=(6, 0))
        ttk.Label(top_bar, text='语言/Language:').pack(side='left')
        self._lang_var = tk.StringVar(value=self.alert_cfg.get('lang', 'zh'))
        _lcb = ttk.Combobox(top_bar, textvariable=self._lang_var, width=8, state='readonly',
                            values=available_langs())
        _lcb.pack(side='left', padx=(4, 10))
        _lcb.bind('<<ComboboxSelected>>', self._on_lang_change)
        ttk.Button(top_bar, text='打开数据目录', command=self._open_data_dir).pack(side='right')
        ttk.Label(top_bar, text='🔍 功能搜索:').pack(side='left', padx=(6, 0))
        self._feat_cb = ttk.Combobox(top_bar, width=22)
        self._feat_cb.pack(side='left', padx=(4, 0))
        self._feat_cb.bind('<KeyRelease>', self._feat_filter)
        self._feat_cb.bind('<<ComboboxSelected>>', self._feat_go)
        self._feat_cb.bind('<Return>', self._feat_go)
        nb = ttk.Notebook(root)
        self.nb = nb
        nb.pack(fill='both', expand=True, padx=8, pady=(8, 4))
        self.tab_ping = ttk.Frame(nb)
        self.tab_port = ttk.Frame(nb)
        self.tab_trace = ttk.Frame(nb)
        self.tab_monitor = ttk.Frame(nb)
        self.tab_diag = ttk.Frame(nb)
        self.tab_qmon = ttk.Frame(nb)
        self.tab_arp = ttk.Frame(nb)
        self.tab_pass = ttk.Frame(nb)
        self.tab_life = ttk.Frame(nb)
        nb.add(self.tab_ping, text=t('  主机存活扫描  '))
        nb.add(self.tab_port, text=t('  端口扫描  '))
        nb.add(self.tab_trace, text=t('  路由追踪 + 地理定位  '))
        nb.add(self.tab_monitor, text=t('  定时监控 + 变更告警  '))
        nb.add(self.tab_diag, text=t('  网络诊断  '))
        nb.add(self.tab_qmon, text=t('  链路质量曲线  '))
        nb.add(self.tab_arp, text=t('  ARP 监听  '))
        nb.add(self.tab_pass, text=t('  加解密编码  '))
        nb.add(self.tab_life, text=t('  生活  '))

        self._build_ping_tab()
        self._build_port_tab()
        self._build_trace_tab()
        self._build_monitor_tab()
        self._build_diag_tab()
        self._build_qmon_tab()
        self._build_arp_tab()
        self._build_pass_tab()
        self._build_life_tab()
        self._build_feature_index()

        foot = ttk.Label(root, foreground='#888',
                         text='⚠ 仅限对你拥有或已获授权的网络进行测试；大范围扫描可能触发对方安全告警。')
        foot.pack(side='bottom', fill='x', padx=10, pady=(0, 6))

        self.root.after(80, self._poll_queue)

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass
        try:
            import tkinter.font as _tkfont
            for _fn in ('TkDefaultFont', 'TkTextFont', 'TkFixedFont', 'TkMenuFont', 'TkHeadingFont', 'TkTooltipFont'):
                try:
                    _tkfont.nametofont(_fn).configure(size=11)
                except Exception:
                    pass
        except Exception:
            pass
        for _st in ('.', 'TButton', 'TLabel', 'TCheckbutton', 'TRadiobutton', 'TEntry',
                    'TCombobox', 'TSpinbox', 'TNotebook.Tab', 'TLabelframe.Label'):
            try:
                style.configure(_st, font=('', 11))
            except Exception:
                pass
        style.configure('Treeview', rowheight=28, font=('', 11))
        style.configure('Treeview.Heading', font=('', 11, 'bold'))
        style.configure('Accent.TButton', font=('', 11, 'bold'))
        style.configure('TNotebook.Tab', font=('', 10), padding=(6, 3))

    # ---------- 公共控件 ----------
    def _make_tree(self, parent, columns, widths):
        wrap = ttk.Frame(parent)
        tree = ttk.Treeview(wrap, columns=columns, show='headings', height=14)
        for c, w in zip(columns, widths):
            tree.heading(c, text=c)
            tree.column(c, width=w, anchor='w')
        vs = ttk.Scrollbar(wrap, orient='vertical', command=tree.yview)
        hs = ttk.Scrollbar(wrap, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        tree.grid(row=0, column=0, sticky='nsew')
        vs.grid(row=0, column=1, sticky='ns')
        hs.grid(row=1, column=0, sticky='ew')
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        return wrap, tree

    def _set_scanning(self, flag):
        self.scanning = flag
        state = 'disabled' if flag else 'normal'
        for b in self.start_buttons:
            b.configure(state=state)

    def _export(self, tree, columns):
        if not tree.get_children():
            messagebox.showinfo('导出', '没有可导出的结果')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.csv',
            filetypes=[('CSV 文件', '*.csv'), ('JSON 文件', '*.json')])
        if not path:
            return
        rows = [tree.item(i, 'values') for i in tree.get_children()]
        try:
            if path.lower().endswith('.json'):
                data = [dict(zip(columns, r)) for r in rows]
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            else:
                with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                    w = csv.writer(f)
                    w.writerow(columns)
                    w.writerows(rows)
            messagebox.showinfo('导出成功', '已保存到:\n%s' % path)
        except Exception as e:
            messagebox.showerror('导出失败', str(e))

    # ---------- Tab 1：主机存活 ----------
    def _build_ping_tab(self):
        f = self.tab_ping
        top = ttk.Frame(f)
        top.pack(fill='x', padx=10, pady=8)

        ttk.Label(top, text='目标 IP 段:').grid(row=0, column=0, sticky='w')
        self.ping_target = ttk.Entry(top, width=42)
        self.ping_target.insert(0, '192.168.1.1-254')
        self.ping_target.grid(row=0, column=1, columnspan=3, sticky='w', padx=6)
        ttk.Label(top, text='(如 192.168.1.0/24、10.0.0.1-50)',
                  foreground='#888').grid(row=0, column=4, sticky='w')

        ttk.Label(top, text='超时(ms):').grid(row=1, column=0, sticky='w', pady=(6, 0))
        self.ping_timeout = ttk.Spinbox(top, from_=200, to=5000, increment=100, width=8)
        self.ping_timeout.set(1000)
        self.ping_timeout.grid(row=1, column=1, sticky='w', padx=6, pady=(6, 0))
        ttk.Label(top, text='并发:').grid(row=1, column=2, sticky='e', pady=(6, 0))
        self.ping_workers = ttk.Spinbox(top, from_=1, to=256, increment=8, width=8)
        self.ping_workers.set(64)
        self.ping_workers.grid(row=1, column=3, sticky='w', padx=6, pady=(6, 0))
        self.ping_only_alive = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text='只显示存活主机',
                        variable=self.ping_only_alive).grid(row=1, column=4, sticky='w', pady=(6, 0))
        self.ping_smart = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text='智能存活(穿透禁Ping)',
                        variable=self.ping_smart).grid(row=2, column=4, sticky='w', pady=(6, 0))

        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=10)
        b1 = ttk.Button(bar, text=t('开始扫描'), style='Accent.TButton', command=self._start_ping)
        b1.pack(side='left')
        self.start_buttons.append(b1)
        ttk.Button(bar, text=t('停止'), command=self._stop).pack(side='left', padx=6)
        cols = ('IP', '状态', '时延(ms)', 'TTL')
        ttk.Button(bar, text=t('导出结果'),
                   command=lambda: self._export(self.ping_tree, cols)).pack(side='left')
        ttk.Button(bar, text=t('清空'),
                   command=lambda: self._clear(self.ping_tree)).pack(side='left', padx=6)

        self.ping_prog = ttk.Progressbar(f, mode='determinate')
        self.ping_prog.pack(fill='x', padx=10, pady=6)
        self.ping_status = ttk.Label(f, text='就绪', foreground='#555')
        self.ping_status.pack(fill='x', padx=10)

        wrap, self.ping_tree = self._make_tree(f, cols, (200, 120, 120, 80))
        wrap.pack(fill='both', expand=True, padx=10, pady=6)
        self.ping_tree.tag_configure('alive', foreground='#137333')
        self.ping_tree.tag_configure('dead', foreground='#b00020')

    def _start_ping(self):
        if self.scanning:
            return
        try:
            targets = expand_targets(self.ping_target.get())
        except Exception as e:
            messagebox.showerror('输入错误', str(e))
            return
        if not self._authz('PING_SWEEP', targets):
            return
        self._clear(self.ping_tree)
        timeout = int(float(self.ping_timeout.get()))
        workers = min(MAX_WORKERS, int(float(self.ping_workers.get())))
        only_alive = self.ping_only_alive.get()
        self.stop_event.clear()
        self._set_scanning(True)
        self.ping_prog.configure(maximum=len(targets), value=0)
        self.ping_status.configure(text='正在扫描 %d 个地址...' % len(targets))
        threading.Thread(target=self._ping_worker,
                         args=(targets, timeout, workers, only_alive, self.ping_smart.get()),
                         daemon=True).start()

    def _ping_worker(self, targets, timeout, workers, only_alive, smart):
        done = alive = 0
        probe = smart_alive if smart else ping_host
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(probe, ip, timeout): ip for ip in targets}
                for fut in concurrent.futures.as_completed(futs):
                    if self.stop_event.is_set():
                        break
                    r = fut.result()
                    done += 1
                    if r['alive']:
                        alive += 1
                    if r['alive'] or not only_alive:
                        self.q.put({'tab': 'ping', 'type': 'row', 'data': r})
                    self.q.put({'tab': 'ping', 'type': 'prog',
                                'done': done, 'alive': alive})
        finally:
            self.q.put({'tab': 'ping', 'type': 'done', 'alive': alive,
                        'total': len(targets)})

    # ---------- Tab 2：端口扫描 (需求 2/3/4) ----------
    def _build_port_tab(self):
        f = self.tab_port
        top = ttk.Frame(f)
        top.pack(fill='x', padx=10, pady=8)

        ttk.Label(top, text='目标:').grid(row=0, column=0, sticky='w')
        self.port_target = ttk.Entry(top, width=46)
        self.port_target.insert(0, '127.0.0.1')
        self.port_target.grid(row=0, column=1, columnspan=3, sticky='w', padx=6)
        ttk.Label(top, text='(单IP / IP段 / 主机名)',
                  foreground='#888').grid(row=0, column=4, sticky='w')

        ttk.Label(top, text='端口:').grid(row=1, column=0, sticky='w', pady=(6, 0))
        self.port_ports = ttk.Entry(top, width=46)
        self.port_ports.insert(0, 'top')
        self.port_ports.grid(row=1, column=1, columnspan=3, sticky='w', padx=6, pady=(6, 0))
        ttk.Label(top, text='(80 / 1-1024 / top / all)',
                  foreground='#888').grid(row=1, column=4, sticky='w', pady=(6, 0))

        ttk.Label(top, text='协议:').grid(row=2, column=0, sticky='w', pady=(6, 0))
        self.port_proto = tk.StringVar(value='TCP')
        pf = ttk.Frame(top)
        pf.grid(row=2, column=1, sticky='w', padx=6, pady=(6, 0))
        for p in ('TCP', 'UDP', 'TCP+UDP'):
            ttk.Radiobutton(pf, text=p, value=p, variable=self.port_proto).pack(side='left', padx=(0, 8))

        ttk.Label(top, text='超时(s):').grid(row=2, column=2, sticky='e', pady=(6, 0))
        self.port_timeout = ttk.Spinbox(top, from_=0.3, to=10, increment=0.3, width=6)
        self.port_timeout.set(1.0)
        self.port_timeout.grid(row=2, column=3, sticky='w', padx=6, pady=(6, 0))

        ttk.Label(top, text='并发:').grid(row=3, column=0, sticky='w', pady=(6, 0))
        self.port_workers = ttk.Spinbox(top, from_=1, to=500, increment=16, width=6)
        self.port_workers.set(128)
        self.port_workers.grid(row=3, column=1, sticky='w', padx=6, pady=(6, 0))

        opts = ttk.Frame(top)
        opts.grid(row=4, column=0, columnspan=5, sticky='w', pady=(8, 0))
        self.port_only_open = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text='只显示开放端口',
                        variable=self.port_only_open).pack(side='left', padx=(0, 14))
        self.port_prefilter = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text='先Ping存活再扫(适合IP段)',
                        variable=self.port_prefilter).pack(side='left', padx=(0, 14))
        self.port_banner = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text='抓取Banner(TCP)',
                        variable=self.port_banner).pack(side='left')
        self.port_fast = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text='高速模式',
                        variable=self.port_fast).pack(side='left', padx=(14, 0))
        self.port_sv = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text='服务识别',
                        variable=self.port_sv).pack(side='left', padx=(14, 0))

        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=10)
        b = ttk.Button(bar, text=t('开始扫描'), style='Accent.TButton', command=self._start_port)
        b.pack(side='left')
        self.start_buttons.append(b)
        ttk.Button(bar, text=t('停止'), command=self._stop).pack(side='left', padx=6)
        cols = ('IP', '端口', '协议', '状态', '服务', 'Banner')
        ttk.Button(bar, text=t('导出结果'),
                   command=lambda: self._export(self.port_tree, cols)).pack(side='left')
        ttk.Button(bar, text=t('清空'),
                   command=lambda: self._clear(self.port_tree)).pack(side='left', padx=6)

        self.port_prog = ttk.Progressbar(f, mode='determinate')
        self.port_prog.pack(fill='x', padx=10, pady=6)
        self.port_status = ttk.Label(f, text='就绪', foreground='#555')
        self.port_status.pack(fill='x', padx=10)

        wrap, self.port_tree = self._make_tree(
            f, cols, (150, 70, 60, 110, 120, 260))
        wrap.pack(fill='both', expand=True, padx=10, pady=6)
        self.port_tree.tag_configure('open', foreground='#137333')
        self.port_tree.tag_configure('maybe', foreground='#a56a00')
        self.port_tree.tag_configure('closed', foreground='#b00020')
        self.port_tree.tag_configure('risk', foreground='#fff', background='#d93025')

    def _start_port(self):
        if self.scanning:
            return
        try:
            targets = expand_targets(self.port_target.get())
            ports = parse_ports(self.port_ports.get())
        except Exception as e:
            messagebox.showerror('输入错误', str(e))
            return
        if not self._authz('PORT_SCAN', targets):
            return
        protos = ['TCP', 'UDP'] if self.port_proto.get() == 'TCP+UDP' else [self.port_proto.get()]
        total = len(targets) * len(ports) * len(protos)
        if total > 200000:
            if not messagebox.askyesno('确认',
                    '本次将探测约 %d 个组合，可能耗时较久，是否继续？' % total):
                return
        self._clear(self.port_tree)
        timeout = float(self.port_timeout.get())
        workers = min(MAX_WORKERS, int(float(self.port_workers.get())))
        self.stop_event.clear()
        self._set_scanning(True)
        self.port_prog.configure(maximum=max(1, total), value=0)
        self.port_status.configure(text='准备扫描...')
        threading.Thread(target=self._port_worker,
                         args=(targets, ports, protos, timeout, workers,
                               self.port_only_open.get(), self.port_prefilter.get(),
                               self.port_banner.get(), self.port_fast.get(),
                               self.port_sv.get()),
                         daemon=True).start()

    def _port_worker(self, targets, ports, protos, timeout, workers,
                     only_open, prefilter, banner, fast, sv):
        opened = 0
        udp_open = udp_unknown = udp_closed = 0
        note = None
        try:
            if prefilter and len(targets) > 1:
                self.q.put({'tab': 'port', 'type': 'status',
                            'text': '正在 Ping 预筛 %d 台主机...' % len(targets)})
                alive = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 128)) as ex:
                    futs = {ex.submit(ping_host, ip, 1000): ip for ip in targets}
                    for fut in concurrent.futures.as_completed(futs):
                        if self.stop_event.is_set():
                            break
                        r = fut.result()
                        if r['alive']:
                            alive.append(r['ip'])
                targets = alive
                if not targets:
                    note = '无存活主机（已跳过端口扫描）'
                    return

            def emit(r):
                nonlocal opened, udp_open, udp_unknown, udp_closed
                is_open = is_open_like(r['state'], r['proto'])
                if r['proto'] == 'UDP':
                    if is_open:
                        udp_open += 1
                    elif r['state'] == 'closed':
                        udp_closed += 1
                    else:
                        udp_unknown += 1
                if is_open:
                    opened += 1
                    if sv and r['proto'] == 'TCP':
                        pv = probe_service(r['ip'], r['port'])
                        r['service'] = r['service'] or pv['service']
                        r['banner'] = (pv['product'] + ' ' + pv['version']).strip() or pv['banner'] or r.get('banner', '')
                    lvl, reason = risk_note(r['port'])
                    if lvl:
                        r['risk'] = lvl
                        r['banner'] = ('⚠%s危 %s' % (lvl, reason)) + ((' | ' + r['banner']) if r.get('banner') else '')
                if is_open or not only_open:
                    self.q.put({'tab': 'port', 'type': 'row', 'data': r})

            if fast and protos == ['TCP']:
                total = len(targets) * len(ports)
                self.q.put({'tab': 'port', 'type': 'maxset', 'total': total})
                self.q.put({'tab': 'port', 'type': 'status', 'text': '高速扫描中（仅显示开放端口）...'})
                fast_scan(targets, ports, timeout=timeout, on_result=emit, stop=self.stop_event)
                self.q.put({'tab': 'port', 'type': 'prog', 'done': total, 'open': opened, 'total': total})
            else:
                tasks = [(ip, p, proto) for ip in targets for proto in protos for p in ports]
                total = len(tasks)
                self.q.put({'tab': 'port', 'type': 'maxset', 'total': total})
                done = 0
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                    futs = [ex.submit(scan_port, ip, p, proto, timeout, banner)
                            for (ip, p, proto) in tasks]
                    for fut in concurrent.futures.as_completed(futs):
                        if self.stop_event.is_set():
                            break
                        r = fut.result()
                        done += 1
                        emit(r)
                        self.q.put({'tab': 'port', 'type': 'prog',
                                    'done': done, 'open': opened, 'total': total})
        finally:
            if note is None and 'UDP' in protos:
                note = ('UDP：%d 确认开放（收到应答）/ %d 无响应（非 root 无法确认，按未开放处理，取消“只显示开放端口”可查看）/ %d 关闭'
                        % (udp_open, udp_unknown, udp_closed))
            self.q.put({'tab': 'port', 'type': 'done', 'open': opened, 'note': note})

    # ---------- Tab 3：路由追踪 ----------
    def _build_trace_tab(self):
        f = self.tab_trace
        top = ttk.Frame(f)
        top.pack(fill='x', padx=10, pady=8)
        ttk.Label(top, text='目标 IP / 域名:').grid(row=0, column=0, sticky='w')
        self.trace_target = ttk.Entry(top, width=40)
        self.trace_target.insert(0, '8.8.8.8')
        self.trace_target.grid(row=0, column=1, sticky='w', padx=6)
        ttk.Label(top, text='最大跳数:').grid(row=0, column=2, sticky='e')
        self.trace_hops = ttk.Spinbox(top, from_=5, to=64, increment=1, width=6)
        self.trace_hops.set(30)
        self.trace_hops.grid(row=0, column=3, sticky='w', padx=6)
        self.trace_geo = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text='查询每跳地理位置/机房',
                        variable=self.trace_geo).grid(row=0, column=4, sticky='w', padx=6)

        geobar = ttk.Frame(f)
        geobar.pack(fill='x', padx=10, pady=(2, 0))
        ttk.Label(geobar, text='地理库：').pack(side='left')
        self.trace_offline = tk.BooleanVar(value=(_GEO.get('mode') == 'offline'))
        ttk.Checkbutton(geobar, text='下载到本地并离线使用(不联网)',
                        variable=self.trace_offline,
                        command=self._trace_toggle_offline).pack(side='left')
        self.trace_geo_dl = ttk.Button(geobar, text='下载/更新离线库(DB-IP City Lite)',
                                       command=self._trace_download_geo)
        self.trace_geo_dl.pack(side='left', padx=8)
        self.trace_geo_lbl = ttk.Label(geobar, text='', foreground='#888')
        self.trace_geo_lbl.pack(side='left', padx=4)

        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=10)
        b = ttk.Button(bar, text=t('开始追踪'), style='Accent.TButton', command=self._start_trace)
        b.pack(side='left')
        self.start_buttons.append(b)
        ttk.Button(bar, text=t('停止'), command=self._stop).pack(side='left', padx=6)
        cols = ('跳', 'IP', '时延(ms)', '国家', '地区', '城市', '运营商/机房(ISP/Org/AS)')
        ttk.Button(bar, text=t('导出结果'),
                   command=lambda: self._export(self.trace_tree, cols)).pack(side='left')
        ttk.Button(bar, text='🌍 世界地图',
                   command=self._open_map).pack(side='left', padx=6)
        ttk.Button(bar, text=t('清空'),
                   command=lambda: self._clear(self.trace_tree)).pack(side='left', padx=6)

        self.trace_status = ttk.Label(f, text='就绪', foreground='#555')
        self.trace_status.pack(fill='x', padx=10, pady=6)
        wrap, self.trace_tree = self._make_tree(
            f, cols, (45, 140, 90, 90, 100, 100, 320))
        wrap.pack(fill='both', expand=True, padx=10, pady=6)
        self._trace_geo_refresh_label()

    def _geodb_path(self):
        return default_geodb_path(self.data_dir)

    def _trace_geo_refresh_label(self):
        p = self._geodb_path()
        if os.path.exists(p):
            try:
                mb = os.path.getsize(p) / (1024 * 1024)
            except OSError:
                mb = 0
            self.trace_geo_lbl.configure(text='本地库已就绪 (%.0f MB)｜离线可查国家/地区/城市' % mb)
        else:
            self.trace_geo_lbl.configure(text='本地库未下载（勾选或点“下载”获取，约 60MB）')
            if self.trace_offline.get():
                self.trace_offline.set(False)
        if self.trace_offline.get() and os.path.exists(p):
            set_geo_config('offline', p)
        else:
            set_geo_config('online', '')

    def _trace_persist_geo(self):
        self.alert_cfg = getattr(self, 'alert_cfg', {}) or {}
        p = self._geodb_path()
        on = self.trace_offline.get() and os.path.exists(p)
        self.alert_cfg['geo'] = {'mode': 'offline' if on else 'online', 'db': p if on else ''}
        try:
            save_config(self.cfg_path, self.alert_cfg)
        except Exception:
            pass

    def _trace_toggle_offline(self):
        p = self._geodb_path()
        if self.trace_offline.get() and not os.path.exists(p):
            self.trace_offline.set(False)
            if messagebox.askyesno('离线地理库',
                                   '尚未下载本地地理库，现在下载吗？\n（DB-IP City Lite，约 60MB 下载 / 约 130MB 硬盘占用，含 IPv4+IPv6）'):
                self._trace_download_geo()
            return
        self._trace_persist_geo()
        self._trace_geo_refresh_label()

    def _trace_download_geo(self):
        self.trace_geo_dl.configure(state='disabled')
        self.trace_status.configure(text='正在下载离线地理库（DB-IP City Lite，约 60MB）...')
        threading.Thread(target=self._trace_geo_worker, daemon=True).start()

    def _trace_geo_worker(self):
        def prog(done, total, tag):
            pct = (done * 100 // total) if total else 0
            self.root.after(0, lambda: self.trace_status.configure(
                text='下载离线库 %s：%d%%（%d/%d MB）' %
                     (tag, pct, done // 1048576, (total // 1048576) if total else 0)))
        try:
            path = download_geodb(self._geodb_path(), progress=prog)

            def ok():
                self.trace_geo_dl.configure(state='normal')
                self.trace_offline.set(True)
                self._trace_persist_geo()
                self._trace_geo_refresh_label()
                self.trace_status.configure(text='离线地理库已就绪，已切换为离线查询（不再联网）')
            self.root.after(0, ok)
        except Exception as e:
            msg = str(e)
            self.root.after(0, lambda: (self.trace_geo_dl.configure(state='normal'),
                                        self.trace_status.configure(text='离线库下载失败：' + msg)))

    def _start_trace(self):
        if self.scanning:
            return
        target = self.trace_target.get().strip()
        if not target:
            messagebox.showerror('输入错误', '请填写目标 IP 或域名')
            return
        if not self._authz('TRACEROUTE', [resolve_host(target) or target]):
            return
        self._clear(self.trace_tree)
        self.trace_results = []
        hops = int(float(self.trace_hops.get()))
        geo = self.trace_geo.get()
        self.stop_event.clear()
        self._set_scanning(True)
        self.trace_status.configure(text='正在追踪到 %s 的路由...' % target)
        threading.Thread(target=self._trace_worker,
                         args=(target, hops, geo), daemon=True).start()

    def _trace_worker(self, target, max_hops, geo):
        try:
            def on_hop(hop):
                if geo and hop.get('ip'):
                    g = geolocate(hop['ip'])
                    hop['geo'] = g
                    time.sleep(0.2)  # 免费接口限速保护
                self.q.put({'tab': 'trace', 'type': 'row', 'data': hop})
            run_traceroute(target, max_hops, on_hop=on_hop, stop_event=self.stop_event)
            self.q.put({'tab': 'trace', 'type': 'done'})
        except FileNotFoundError:
            self.q.put({'tab': 'trace', 'type': 'error',
                        'text': '未找到 traceroute/tracert 命令。'
                                'Linux 可安装: sudo apt install traceroute'})
        except Exception as e:
            self.q.put({'tab': 'trace', 'type': 'error', 'text': str(e)})

    def _open_map(self):
        hops = [h for h in self.trace_results
                if (h.get('geo') or {}).get('lat') is not None]
        if not hops:
            messagebox.showinfo(
                '世界地图',
                '暂无可定位的路由跳点。\n请先勾选“查询每跳地理位置/机房”并完成一次追踪，\n'
                '公网跳点才会有经纬度（内网地址无法定位）。')
            return
        try:
            page = build_map_html(self.trace_target.get().strip(), self.trace_results)
            fd, path = tempfile.mkstemp(prefix='netprobe_map_', suffix='.html')
            with os.fdopen(fd, 'w', encoding='utf-8') as fp:
                fp.write(page)
            webbrowser.open('file://' + path)
            self.trace_status.configure(text='已在浏览器打开世界地图（需联网加载地图瓦片）')
        except Exception as e:
            messagebox.showerror('世界地图', str(e))

    # ---------- Tab 4：定时监控 + 变更告警 ----------
    def _build_monitor_tab(self):
        f = self.tab_monitor
        top = ttk.Frame(f)
        top.pack(fill='x', padx=10, pady=8)

        ttk.Label(top, text='监控目标:').grid(row=0, column=0, sticky='w')
        self.mon_target = tk.Text(top, width=42, height=4, wrap='none')
        self.mon_target.insert('1.0', '192.168.1.1-50')
        self.mon_target.grid(row=0, column=1, columnspan=3, sticky='we', padx=6)
        ttk.Label(top, text='(IP段/主机名；端口模式可填 IP:端口 或 域名:端口 批量)',
                  foreground='#888').grid(row=0, column=4, sticky='w')

        ttk.Label(top, text='监控类型:').grid(row=1, column=0, sticky='w', pady=(6, 0))
        self.mon_type = tk.StringVar(value='ping')
        tf = ttk.Frame(top)
        tf.grid(row=1, column=1, sticky='w', padx=6, pady=(6, 0))
        ttk.Radiobutton(tf, text='主机存活（上线/下线）', value='ping',
                        variable=self.mon_type).pack(side='left', padx=(0, 10))
        ttk.Radiobutton(tf, text='端口开放（开放/关闭）', value='port',
                        variable=self.mon_type).pack(side='left')

        ttk.Label(top, text='端口:').grid(row=2, column=0, sticky='w', pady=(6, 0))
        self.mon_ports = ttk.Entry(top, width=28)
        self.mon_ports.insert(0, '22,80,443')
        self.mon_ports.grid(row=2, column=1, sticky='w', padx=6, pady=(6, 0))
        self.mon_proto = tk.StringVar(value='TCP')
        pf = ttk.Frame(top)
        pf.grid(row=2, column=2, columnspan=2, sticky='w', pady=(6, 0))
        ttk.Radiobutton(pf, text='TCP', value='TCP', variable=self.mon_proto).pack(side='left', padx=(0, 8))
        ttk.Radiobutton(pf, text='UDP', value='UDP', variable=self.mon_proto).pack(side='left')
        ttk.Label(top, text='(仅端口监控用)', foreground='#888').grid(row=2, column=4, sticky='w', pady=(6, 0))

        ttk.Label(top, text='间隔(分钟):').grid(row=3, column=0, sticky='w', pady=(6, 0))
        self.mon_interval = ttk.Spinbox(top, from_=1, to=1440, increment=1, width=6)
        self.mon_interval.set(5)
        self.mon_interval.grid(row=3, column=1, sticky='w', padx=6, pady=(6, 0))

        optf = ttk.Frame(top)
        optf.grid(row=4, column=0, columnspan=5, sticky='w', pady=(8, 0))
        self.mon_popup = tk.BooleanVar(value=True)
        ttk.Checkbutton(optf, text='变更时弹窗 + 提示音',
                        variable=self.mon_popup).pack(side='left', padx=(0, 14))
        self.mon_log = tk.BooleanVar(value=True)
        ttk.Checkbutton(optf, text='变更写入日志文件(CSV)',
                        variable=self.mon_log).pack(side='left')

        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=10)
        self.mon_start_btn = ttk.Button(bar, text=t('开始监控'), style='Accent.TButton',
                                        command=self._start_monitor)
        self.mon_start_btn.pack(side='left')
        self.mon_stop_btn = ttk.Button(bar, text=t('停止监控'), command=self._stop_monitor,
                                       state='disabled')
        self.mon_stop_btn.pack(side='left', padx=6)
        cols = ('时间', '变更类型', '目标', '详情')
        ttk.Button(bar, text=t('导出变更'),
                   command=lambda: self._export(self.mon_tree, cols)).pack(side='left')
        ttk.Button(bar, text=t('设置…'),
                   command=self._open_alert_settings).pack(side='left', padx=6)
        ttk.Button(bar, text=t('导出报表'),
                   command=self._export_report).pack(side='left')
        ttk.Button(bar, text=t('汇总看板…'),
                   command=self._open_dashboard).pack(side='left', padx=6)
        ttk.Button(bar, text=t('清空'),
                   command=lambda: self._clear(self.mon_tree)).pack(side='left', padx=6)

        self.mon_status = ttk.Label(f, text='未运行', foreground='#555')
        self.mon_status.pack(fill='x', padx=10, pady=6)
        wrap, self.mon_tree = self._make_tree(f, cols, (150, 130, 190, 360))
        wrap.pack(fill='both', expand=True, padx=10, pady=6)
        self.mon_tree.tag_configure('up', foreground='#137333')
        self.mon_tree.tag_configure('down', foreground='#b00020')
        self.mon_tree.tag_configure('base', foreground='#555')

    def _start_monitor(self):
        if self.monitoring:
            return
        mode = self.mon_type.get()
        text = self.mon_target.get('1.0', 'end')
        endpoints = []
        try:
            # 先逐行解析：能解析成“目标:端口”的是明确端点，其余当普通目标
            explicit, plains = [], []
            for tok in re.split(r'[\s,]+', text.strip()):
                if not tok:
                    continue
                ep = parse_endpoints(tok)
                if ep:
                    explicit += ep
                else:
                    plains.append(tok)
            # 只要出现“目标:端口”形式，就自动按“端口监控”处理（该目标监听它附带的端口）
            if explicit:
                mode = 'port'
            if mode == 'port':
                plain_ips = expand_targets(' '.join(plains), max_hosts=1000000) if plains else []
                pports = parse_ports(self.mon_ports.get()) if plain_ips else []
                endpoints = explicit + [(ip, p) for ip in plain_ips for p in pports]
                if not endpoints:
                    raise ValueError('未解析到监控端点（每行填 目标 或 目标:端口，可多行；'
                                     '不带端口的目标使用下方“端口”框里的端口）')
                targets = sorted({ip for ip, _p in endpoints})
                ports = []
            else:
                targets = expand_targets(text, max_hosts=1000000)
                ports = []
                if not targets:
                    raise ValueError('未解析到监控主机')
        except Exception as e:
            messagebox.showerror('输入错误', str(e))
            return
        self.mon_type.set(mode)  # 若因 目标:端口 自动切到端口监控，同步界面单选按钮
        if not self._authz('MONITOR', targets):
            return
        cfg = {'targets': targets, 'endpoints': endpoints, 'mode': mode, 'ports': ports,
               'proto': self.mon_proto.get(),
               'interval': int(float(self.mon_interval.get())) * 60,
               'popup': self.mon_popup.get(), 'log': self.mon_log.get()}
        self.monitor_stop.clear()
        self.monitoring = True
        self.mon_start_btn.configure(state='disabled')
        self.mon_stop_btn.configure(state='normal')
        self.mon_status.configure(text='监控已启动，正在建立基线...')
        threading.Thread(target=self._monitor_worker, args=(cfg,), daemon=True).start()

    def _stop_monitor(self):
        if self.monitoring:
            self.monitor_stop.set()
            self.mon_status.configure(text='正在停止监控...')

    def _monitor_scan_once(self, cfg):
        """执行一轮扫描，返回快照集合。ping: {ip}; port: {'ip:port/PROTO'}"""
        targets = cfg['targets']
        cur = set()
        if cfg['mode'] == 'ping':
            workers = min(128, max(8, len(targets)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                for r in ex.map(lambda ip: ping_host(ip, 1000), targets):
                    if r['alive']:
                        cur.add(r['ip'])
        else:
            proto = cfg['proto']
            if cfg.get('endpoints'):
                tasks = list(cfg['endpoints'])
            else:
                tasks = [(ip, p) for ip in targets for p in cfg['ports']]
            workers = min(300, max(16, len(tasks)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                for r in ex.map(lambda t: scan_port(t[0], t[1], proto, 1.5), tasks):
                    # 监控“在线”判定：TCP 需建连成功；UDP 只要未被明确拒绝(closed)即视为在线，
                    # 以适配 WireGuard 等静默服务（它们永不回包，但端口确实开放）。
                    up = (r['state'] == 'open') if r['proto'] == 'TCP' else (r['state'] != 'closed')
                    if up:
                        cur.add('%s:%d/%s' % (r['ip'], r['port'], r['proto']))
        return cur

    def _monitor_worker(self, cfg):
        prev = None
        cycle = 0
        up_kind = '上线' if cfg['mode'] == 'ping' else '端口开放'
        down_kind = '下线' if cfg['mode'] == 'ping' else '端口关闭'
        log_path = os.path.join(self.data_dir, 'netprobe_monitor_log.csv')
        try:
            while not self.monitor_stop.is_set():
                cycle += 1
                self.q.put({'tab': 'monitor', 'type': 'status',
                            'text': '第 %d 轮扫描中...' % cycle})
                try:
                    cur = self._monitor_scan_once(cfg)
                except Exception as e:
                    self.q.put({'tab': 'monitor', 'type': 'status',
                                'text': '扫描出错: %s' % e})
                    cur = prev if prev is not None else set()
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                changes = []
                if prev is None:
                    self.q.put({'tab': 'monitor', 'type': 'row', 'tag': 'base',
                                'time': ts, 'kind': '基线',
                                'target': '存活主机' if cfg['mode'] == 'ping' else '开放端口',
                                'detail': '建立基线，共 %d 项' % len(cur)})
                else:
                    added, removed = diff_snapshots(prev, cur)
                    for x in sorted(added):
                        changes.append((up_kind, x))
                        self.q.put({'tab': 'monitor', 'type': 'row', 'tag': 'up',
                                    'time': ts, 'kind': up_kind,
                                    'target': x.split(':')[0], 'detail': x})
                    for x in sorted(removed):
                        changes.append((down_kind, x))
                        self.q.put({'tab': 'monitor', 'type': 'row', 'tag': 'down',
                                    'time': ts, 'kind': down_kind,
                                    'target': x.split(':')[0], 'detail': x})
                prev = cur

                if cfg['log'] and changes:
                    try:
                        new_file = not os.path.exists(log_path)
                        with open(log_path, 'a', newline='', encoding='utf-8-sig') as fp:
                            w = csv.writer(fp)
                            if new_file:
                                w.writerow(['时间', '变更类型', '详情'])
                            for k, x in changes:
                                w.writerow([ts, k, x])
                    except Exception:
                        pass

                try:
                    conn = db_connect(self.db_path)
                    if changes:
                        db_add_events(conn, [(ts, cfg['mode'], k, x.split(':')[0], x)
                                             for k, x in changes])
                    db_add_cycle(conn, ts, cfg['mode'],
                                 ','.join(cfg['targets'][:3]) + ('...' if len(cfg['targets']) > 3 else ''),
                                 len(cur), len(changes))
                    conn.close()
                except Exception:
                    pass

                if changes:
                    self._notify_channels(cfg['mode'], ts, changes)

                if changes and cfg['popup']:
                    self.q.put({'tab': 'monitor', 'type': 'alert', 'count': len(changes),
                                'lines': ['%s  %s' % (k, x) for k, x in changes[:12]]})

                self.q.put({'tab': 'monitor', 'type': 'status',
                            'text': '第 %d 轮完成 @ %s ｜当前 %d 项 ｜本轮变更 %d 项｜日志: %s'
                            % (cycle, ts, len(cur), len(changes),
                               log_path if cfg['log'] else '未启用')})

                waited = 0.0
                while waited < cfg['interval'] and not self.monitor_stop.is_set():
                    time.sleep(0.5)
                    waited += 0.5
        finally:
            self.q.put({'tab': 'monitor', 'type': 'stopped'})

    def _notify_channels(self, mode, ts, changes):
        wh = self.alert_cfg.get('webhook', {})
        em = self.alert_cfg.get('email', {})
        if not (wh.get('enabled') or em.get('enabled')):
            return
        head = '【UU889 监控告警】%s ｜ %d 项变更' % (ts, len(changes))
        body = head + '\n' + '\n'.join('· %s  %s' % (k, x) for k, x in changes[:20])
        if len(changes) > 20:
            body += '\n… 其余 %d 项' % (len(changes) - 20)

        def work():
            if wh.get('enabled') and wh.get('url'):
                ok, msg = send_webhook(wh['url'], wh.get('type', 'generic'), body)
                self.q.put({'tab': 'monitor', 'type': 'status',
                            'text': 'Webhook 告警%s（%s）' % ('已发送' if ok else '失败', msg)})
            if em.get('enabled'):
                ok, msg = send_email(em, head, body)
                self.q.put({'tab': 'monitor', 'type': 'status',
                            'text': '邮件告警%s（%s）' % ('已发送' if ok else '失败', msg)})
        threading.Thread(target=work, daemon=True).start()

    def _export_report(self):
        try:
            conn = db_connect(self.db_path)
            events = db_fetch_events(conn)
            conn.close()
        except Exception as e:
            messagebox.showerror('导出报表', '读取数据库失败：%s' % e)
            return
        if not events:
            messagebox.showinfo('导出报表', '数据库暂无监控变更记录，先运行一段时间监控再导出。\n数据库位置：%s' % self.db_path)
            return
        try:
            page = build_report_html(events)
            fd, path = tempfile.mkstemp(prefix='netprobe_report_', suffix='.html')
            with os.fdopen(fd, 'w', encoding='utf-8') as fp:
                fp.write(page)
            webbrowser.open('file://' + path)
            self.mon_status.configure(text='报表已在浏览器打开（%d 条事件）' % len(events))
        except Exception as e:
            messagebox.showerror('导出报表', str(e))

    def _open_dashboard(self):
        paths = filedialog.askopenfilenames(
            title='选择要汇总的 netprobe.db（本机数据库在 %s）' % self.data_dir,
            initialdir=self.data_dir,
            filetypes=[('SQLite 数据库', '*.db'), ('所有文件', '*.*')])
        if not paths:
            return
        sources = [read_db_summary(p) for p in paths]
        try:
            page = build_dashboard_html(sources)
            fd, path = tempfile.mkstemp(prefix='netprobe_dashboard_', suffix='.html')
            with os.fdopen(fd, 'w', encoding='utf-8') as fp:
                fp.write(page)
            webbrowser.open('file://' + path)
            self.mon_status.configure(text='汇总看板已打开（%d 台设备，%d 条事件）'
                                      % (len(sources), sum(s['total'] for s in sources)))
        except Exception as e:
            messagebox.showerror('汇总看板', str(e))

    def _open_alert_settings(self):
        cfg = self.alert_cfg
        win = tk.Toplevel(self.root)
        win.title('设置：告警渠道 / 授权白名单 / 离线地理库')
        win.transient(self.root)
        win.resizable(False, False)
        pad = {'padx': 6, 'pady': 3}

        wf = ttk.LabelFrame(win, text='Webhook（Slack/钉钉/企业微信/飞书/Discord/通用）')
        wf.grid(row=0, column=0, sticky='ew', padx=10, pady=(10, 4))
        wh_en = tk.BooleanVar(value=cfg['webhook'].get('enabled', False))
        ttk.Checkbutton(wf, text='启用 Webhook 告警', variable=wh_en).grid(row=0, column=0, columnspan=2, sticky='w', **pad)
        ttk.Label(wf, text='类型:').grid(row=1, column=0, sticky='e', **pad)
        wh_type = tk.StringVar(value=cfg['webhook'].get('type', 'generic'))
        ttk.Combobox(wf, textvariable=wh_type, width=16, state='readonly',
                     values=['generic', 'slack', 'dingtalk', 'wechat', 'feishu', 'discord']
                     ).grid(row=1, column=1, sticky='w', **pad)
        ttk.Label(wf, text='URL:').grid(row=2, column=0, sticky='e', **pad)
        wh_url = ttk.Entry(wf, width=52)
        wh_url.insert(0, cfg['webhook'].get('url', ''))
        wh_url.grid(row=2, column=1, sticky='w', **pad)

        ef = ttk.LabelFrame(win, text='邮件（SMTP）')
        ef.grid(row=1, column=0, sticky='ew', padx=10, pady=4)
        em_en = tk.BooleanVar(value=cfg['email'].get('enabled', False))
        ttk.Checkbutton(ef, text='启用邮件告警', variable=em_en).grid(row=0, column=0, columnspan=4, sticky='w', **pad)
        e = {}

        def field(r, c, label, key, width=20, show=None):
            ttk.Label(ef, text=label).grid(row=r, column=c, sticky='e', **pad)
            ent = ttk.Entry(ef, width=width, show=show)
            ent.insert(0, str(cfg['email'].get(key, '')))
            ent.grid(row=r, column=c + 1, sticky='w', **pad)
            e[key] = ent

        field(1, 0, 'SMTP 服务器:', 'host', 24)
        field(1, 2, '端口:', 'port', 8)
        em_ssl = tk.BooleanVar(value=cfg['email'].get('ssl', True))
        ttk.Checkbutton(ef, text='SSL', variable=em_ssl).grid(row=1, column=4, sticky='w', **pad)
        field(2, 0, '用户名:', 'user', 24)
        field(2, 2, '密码/授权码:', 'password', 16, show='*')
        field(3, 0, '发件人:', 'sender', 24)
        field(3, 2, '收件人(逗号分隔):', 'to', 16)

        gf = ttk.LabelFrame(win, text='授权白名单 & 离线地理库')
        gf.grid(row=2, column=0, sticky='ew', padx=10, pady=4)
        ttk.Label(gf, text='授权网段（每行一个 CIDR，留空=不限制）:').grid(row=0, column=0, columnspan=4, sticky='w', **pad)
        al_txt = tk.Text(gf, width=52, height=3)
        al_txt.insert('1.0', '\n'.join(cfg.get('allowlist', [])))
        al_txt.grid(row=1, column=0, columnspan=4, sticky='w', padx=6, pady=(0, 4))
        ttk.Label(gf, text='离线库模式:').grid(row=2, column=0, sticky='e', **pad)
        geo_mode = tk.StringVar(value=cfg.get('geo', {}).get('mode', 'auto'))
        ttk.Combobox(gf, textvariable=geo_mode, width=10, state='readonly',
                     values=['auto', 'online', 'offline']).grid(row=2, column=1, sticky='w', **pad)
        ttk.Label(gf, text='GeoLite2 .mmdb:').grid(row=2, column=2, sticky='e', **pad)
        geo_db = ttk.Entry(gf, width=22)
        geo_db.insert(0, cfg.get('geo', {}).get('db', ''))
        geo_db.grid(row=2, column=3, sticky='w', **pad)
        ttk.Label(gf, text='界面语言:').grid(row=3, column=0, sticky='e', **pad)
        lang_var = tk.StringVar(value=cfg.get('lang', 'zh'))
        ttk.Combobox(gf, textvariable=lang_var, width=12, state='readonly',
                     values=available_langs()).grid(row=3, column=1, sticky='w', **pad)
        ttk.Label(gf, text='(切换后重启生效；语言包放 <数据目录>\\lang\\*.json)',
                  foreground='#888').grid(row=3, column=2, columnspan=2, sticky='w', **pad)

        def collect():
            return {
                'webhook': {'enabled': wh_en.get(), 'type': wh_type.get(), 'url': wh_url.get().strip()},
                'email': {'enabled': em_en.get(), 'host': e['host'].get().strip(),
                          'port': int(float(e['port'].get() or 465)), 'ssl': em_ssl.get(),
                          'user': e['user'].get().strip(), 'password': e['password'].get(),
                          'sender': e['sender'].get().strip(), 'to': e['to'].get().strip()},
                'geo': {'mode': geo_mode.get(), 'db': geo_db.get().strip()},
                'allowlist': [x.strip() for x in al_txt.get('1.0', 'end').splitlines() if x.strip()],
                'lang': lang_var.get(),
            }

        def do_save():
            self.alert_cfg = collect()
            set_geo_config(self.alert_cfg['geo']['mode'], self.alert_cfg['geo']['db'])
            set_lang(self.alert_cfg['lang'])
            try:
                save_config(self.cfg_path, self.alert_cfg)
                messagebox.showinfo('设置', '已保存到 %s\n（界面语言切换后请重启程序生效）' % self.cfg_path, parent=win)
            except Exception as ex:
                messagebox.showerror('设置', str(ex), parent=win)

        def do_test():
            c = collect()
            self.alert_cfg = c

            def w():
                msgs = []
                if c['webhook']['enabled'] and c['webhook']['url']:
                    ok, mm = send_webhook(c['webhook']['url'], c['webhook']['type'], '【UU889】这是一条测试告警')
                    msgs.append('Webhook: %s (%s)' % ('成功' if ok else '失败', mm))
                if c['email']['enabled']:
                    ok, mm = send_email(c['email'], 'UU889 测试告警', '这是一条测试告警')
                    msgs.append('邮件: %s (%s)' % ('成功' if ok else '失败', mm))
                if not msgs:
                    msgs.append('未启用任何渠道')
                self.q.put({'tab': 'monitor', 'type': 'toast', 'title': '测试结果', 'text': '\n'.join(msgs)})
            threading.Thread(target=w, daemon=True).start()

        btns = ttk.Frame(win)
        btns.grid(row=3, column=0, sticky='e', padx=10, pady=(6, 10))
        ttk.Button(btns, text='发送测试', command=do_test).pack(side='left', padx=4)
        ttk.Button(btns, text='保存', command=do_save).pack(side='left', padx=4)
        ttk.Button(btns, text='关闭', command=win.destroy).pack(side='left', padx=4)

    def _build_diag_tab(self):
        f = self.tab_diag
        top = ttk.Frame(f)
        top.pack(fill='x', padx=10, pady=8)
        ttk.Label(top, text='目标（IP / 域名 / URL / host:port）:').grid(row=0, column=0, sticky='w')
        self.diag_target = ttk.Entry(top, width=46)
        self.diag_target.insert(0, 'www.example.com')
        self.diag_target.grid(row=0, column=1, columnspan=4, sticky='w', padx=6)

        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=10)
        bar2 = ttk.Frame(f)
        bar2.pack(fill='x', padx=10, pady=(4, 0))
        _diag_btns = (('DNS(rDNS)解析', 'dns'), ('DNS查询', 'dnsq'), ('Whois', 'whois'),
                      ('CIDR计算', 'cidr'), ('IP归属地', 'ipinfo'), ('HTTP 检查', 'http'),
                      ('TLS 证书', 'tls'), ('Ping 质量', 'quality'), ('MTU 探测', 'mtu'))
        for _i, (txt, kind) in enumerate(_diag_btns):
            _p = bar if _i < 5 else bar2
            b = ttk.Button(_p, text=txt, command=lambda k=kind: self._run_diag(k))
            b.pack(side='left', padx=(0, 6))
            self.start_buttons.append(b)
        ttk.Button(bar2, text=t('清空'),
                   command=lambda: self.diag_out.delete('1.0', 'end')).pack(side='left', padx=6)

        self.diag_status = ttk.Label(f, text='就绪（DNS/HTTP/TLS 需要联网）', foreground='#555')
        self.diag_status.pack(fill='x', padx=10, pady=6)
        wrap = ttk.Frame(f)
        wrap.pack(fill='both', expand=True, padx=10, pady=6)
        self.diag_out = tk.Text(wrap, wrap='word', height=18)
        vs = ttk.Scrollbar(wrap, orient='vertical', command=self.diag_out.yview)
        self.diag_out.configure(yscrollcommand=vs.set)
        self.diag_out.pack(side='left', fill='both', expand=True)
        vs.pack(side='right', fill='y')

    def _run_diag(self, kind):
        if self.scanning:
            return
        target = self.diag_target.get().strip()
        if not target:
            messagebox.showerror('网络诊断', '请填写目标')
            return
        self.stop_event.clear()
        self._set_scanning(True)
        self.diag_status.configure(text='执行 %s ...' % kind)
        threading.Thread(target=self._diag_worker, args=(kind, target), daemon=True).start()

    def _diag_worker(self, kind, target):
        try:
            if kind == 'dns':
                r = dns_lookup(target)
                text = '【DNS(rDNS)解析】%s\n正向: %s\n反向: %s%s' % (
                    target, ', '.join(r['forward']) or '-', r['reverse'] or '-',
                    ('\n注: ' + r['error']) if r['error'] else '')
            elif kind == 'dnsq':
                if _is_ip(target) or '.' not in target:
                    text = '【DNS 查询】“%s” 不是域名格式，请输入域名（如 example.com）再查 A/MX/CNAME/TXT 等记录。' % target
                else:
                    d = dns_query(target)
                    lines = ['【DNS 查询】%s' % target]
                    for qt in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'):
                        for _tp, val in (d['records'].get(qt) or []):
                            lines.append('  %-6s %s' % (qt, val))
                    if d.get('error'):
                        lines.append('  注: ' + d['error'])
                    if len(lines) == 1:
                        lines.append('  （未查到记录）')
                    text = '\n'.join(lines)
            elif kind == 'whois':
                w = whois_query(target)
                text = ('【Whois】%s ｜ 服务器: %s%s\n' % (
                        w['target'], w.get('server', '-'),
                        ('\n注: ' + w['error']) if w.get('error') else '')) + ('-' * 40) + '\n' + (w.get('text') or '（无返回）')
            elif kind == 'cidr':
                try:
                    info = cidr_info(target)
                    text = '【CIDR 计算】\n' + '\n'.join('%s: %s' % (k, v) for k, v in info.items())
                except Exception as ce:
                    text = '【CIDR 计算】输入无效：请填写形如 192.168.1.0/24 或 2001:db8::/48 的网段。(%s)' % ce
            elif kind == 'http':
                r = http_check(target)
                tls = ''
                if r.get('tls'):
                    t = r['tls']
                    tls = '\nTLS: %s ｜ 颁发者 %s ｜ 剩余 %s 天' % (
                        t.get('version'), t.get('issuer'), t.get('days_left'))
                text = '【HTTP 检查】%s\n状态码: %s %s ｜ 耗时 %s ms ｜ 重定向 %s ｜ Server: %s%s%s' % (
                    r['final_url'], r['status'], r['reason'], r['elapsed_ms'], r['redirects'],
                    r['server'] or '-', tls, ('\n错误: ' + r['error']) if r['error'] else '')
            elif kind == 'tls':
                host, _, port = target.replace('https://', '').replace('http://', '').partition(':')
                host = host.split('/')[0]
                r = tls_check(host, int(port) if port[:4].isdigit() else 443)
                if r['ok']:
                    text = '【TLS 证书】%s:%s\n主体: %s\n颁发者: %s\n到期: %s（剩 %s 天）\n协议: %s\nSAN: %s' % (
                        r['host'], r['port'], r['subject'], r['issuer'], r['not_after'],
                        r['days_left'], r['version'], ', '.join(r['san'][:10]))
                else:
                    text = '【TLS 证书】%s 失败: %s' % (target, r['error'])
            elif kind == 'mtu':
                r = discover_mtu(target)
                text = '【MTU 探测】%s (%s)\nMTU: %s%s' % (
                    target, r['ip'], r['mtu'] if r['mtu'] else '未知',
                    ('  ' + r['note']) if r['note'] else '')
            elif kind == 'ipinfo':
                r = ip_info(target)
                if r['error']:
                    text = '【IP 归属地】%s 失败: %s' % (target, r['error'])
                else:
                    lines = ['【IP 归属地】%s → %d 个地址' % (target, len(r['records']))]
                    for rec in r['records']:
                        lines.append('%s (%s)  rDNS: %s' % (rec['ip'], rec['family'], rec['rdns'] or '-'))
                        lines.append('    %s %s %s ｜ %s ｜ %s' % (
                            rec['country'], rec['region'], rec['city'],
                            rec['isp'] or rec['org'] or '-', rec['asn'] or '-'))
                    text = '\n'.join(lines)
            else:
                ip = resolve_host(target) or target
                r = ping_quality(ip, 5)
                text = '【Ping 质量】%s (%s)\n丢包率: %s%% ｜ 收发 %d/%d\n时延 min/avg/max: %s / %s / %s ms ｜ 抖动: %s ms' % (
                    target, ip, r['loss_pct'], r['recv'], r['sent'], r['min'], r['avg'], r['max'], r['jitter'])
            self.q.put({'tab': 'diag', 'type': 'out', 'text': text})
        except Exception as e:
            self.q.put({'tab': 'diag', 'type': 'out', 'text': '出错: %s' % e})
        finally:
            self.q.put({'tab': 'diag', 'type': 'done'})

    def _authz(self, action, targets):
        ok, bad = check_authorized(targets, self.alert_cfg.get('allowlist', []))
        detail = '%d 个目标' % len(targets)
        if not ok:
            detail += ' 越权:' + ','.join(bad[:5])
        audit_log(self.audit_path, action, detail)
        if not ok:
            messagebox.showerror('未授权',
                '以下目标不在授权白名单内，已阻止本次操作：\n%s\n\n可在“设置…”中配置授权网段。'
                % ', '.join(bad[:10]))
        return ok

    def _build_qmon_tab(self):
        f = self.tab_qmon
        top = ttk.Frame(f)
        top.pack(fill='x', padx=10, pady=8)
        ttk.Label(top, text='目标 IP/域名:').grid(row=0, column=0, sticky='w')
        self.qmon_target = ttk.Entry(top, width=32)
        self.qmon_target.insert(0, '8.8.8.8')
        self.qmon_target.grid(row=0, column=1, sticky='w', padx=6)
        ttk.Label(top, text='间隔(ms):').grid(row=0, column=2, sticky='e')
        self.qmon_interval = ttk.Spinbox(top, from_=200, to=10000, increment=100, width=7)
        self.qmon_interval.set(1000)
        self.qmon_interval.grid(row=0, column=3, sticky='w', padx=6)

        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=10)
        self.qmon_start_btn = ttk.Button(bar, text=t('开始监测'), style='Accent.TButton', command=self._start_qmon)
        self.qmon_start_btn.pack(side='left')
        self.qmon_stop_btn = ttk.Button(bar, text=t('停止'), command=self._stop_qmon, state='disabled')
        self.qmon_stop_btn.pack(side='left', padx=6)

        self.qmon_status = ttk.Label(f, text='就绪（连续 Ping，实时绘制 RTT 曲线与丢包）', foreground='#555')
        self.qmon_status.pack(fill='x', padx=10, pady=(6, 0))
        self.qmon_stats_lbl = ttk.Label(f, text='—', foreground='#333')
        self.qmon_stats_lbl.pack(fill='x', padx=10)
        self.qmon_canvas = tk.Canvas(f, height=260, background='#ffffff',
                                     highlightthickness=1, highlightbackground='#ddd')
        self.qmon_canvas.pack(fill='both', expand=True, padx=10, pady=8)
        self.qmon_canvas.bind('<Configure>', lambda e: self._draw_qmon())

    def _start_qmon(self):
        if self.qmon_running:
            return
        target = self.qmon_target.get().strip()
        ip = resolve_host(target)
        if not ip:
            messagebox.showerror('链路质量', '无法解析目标: %s' % target)
            return
        interval = max(0.2, float(self.qmon_interval.get()) / 1000.0)
        self.qmon_data = []
        self.qmon_stop.clear()
        self.qmon_running = True
        self.qmon_start_btn.configure(state='disabled')
        self.qmon_stop_btn.configure(state='normal')
        self.qmon_status.configure(text='监测 %s (%s) 中…' % (target, ip))
        threading.Thread(target=self._qmon_worker, args=(ip, interval), daemon=True).start()

    def _stop_qmon(self):
        if self.qmon_running:
            self.qmon_stop.set()
            self.qmon_status.configure(text='正在停止…')

    def _qmon_worker(self, ip, interval):
        try:
            while not self.qmon_stop.is_set():
                r = ping_host(ip, 1000)
                self.q.put({'tab': 'qmon', 'type': 'sample',
                            'rtt': r['rtt_ms'] if r['alive'] else None})
                waited = 0.0
                while waited < interval and not self.qmon_stop.is_set():
                    time.sleep(0.1)
                    waited += 0.1
        finally:
            self.q.put({'tab': 'qmon', 'type': 'stopped'})

    def _draw_qmon(self):
        c = self.qmon_canvas
        c.delete('all')
        w = c.winfo_width() or 700
        h = c.winfo_height() or 260
        data = self.qmon_data
        pad_l, pad_b, pad_t, pad_r = 46, 22, 12, 12
        x0, y0, x1, y1 = pad_l, pad_t, w - pad_r, h - pad_b
        c.create_line(x0, y0, x0, y1, fill='#ccc')
        c.create_line(x0, y1, x1, y1, fill='#ccc')
        rtts = [v for v in data if v is not None]
        ymax = max(1.0, (max(rtts) * 1.2) if rtts else 1.0)
        for frac in (0.0, 0.5, 1.0):
            yy = y1 - (y1 - y0) * frac
            c.create_line(x0, yy, x1, yy, fill='#eee')
            c.create_text(x0 - 5, yy, anchor='e', fill='#888', font=('', 8), text='%.0f' % (ymax * frac))
        c.create_text(x0 - 5, y0 - 2, anchor='e', fill='#888', font=('', 8), text='ms')
        n = len(data)
        if n >= 1:
            step = (x1 - x0) / max(1, self.qmon_max - 1)
            seg = []
            for i, v in enumerate(data):
                x = x0 + i * step
                if v is None:
                    c.create_line(x, y1, x, y1 - 8, fill='#d93025', width=2)
                    if len(seg) >= 4:
                        c.create_line(seg, fill='#137333', width=2, smooth=True)
                    seg = []
                else:
                    y = y1 - (y1 - y0) * min(1.0, v / ymax)
                    seg += [x, y]
            if len(seg) >= 4:
                c.create_line(seg, fill='#137333', width=2, smooth=True)

    def _on_lang_change(self, _e=None):
        self.alert_cfg['lang'] = self._lang_var.get()
        set_lang(self._lang_var.get())
        try:
            save_config(self.cfg_path, self.alert_cfg)
        except Exception:
            pass
        messagebox.showinfo('语言 / Language',
                            '已切换为「%s」，请重启程序完全生效。\nRestart to fully apply.' % self._lang_var.get())

    def _open_data_dir(self):
        d = self.data_dir
        try:
            if IS_WINDOWS:
                os.startfile(d)
            elif IS_MAC:
                subprocess.Popen(['open', d])
            else:
                subprocess.Popen(['xdg-open', d])
        except Exception:
            messagebox.showinfo('数据目录', d)

    def _build_arp_tab(self):
        f = self.tab_arp
        bar = ttk.Frame(f)
        bar.pack(fill='x', padx=10, pady=8)
        b = ttk.Button(bar, text='刷新 ARP 表', style='Accent.TButton', command=lambda: self._arp_refresh(False))
        b.pack(side='left')
        self.start_buttons.append(b)
        b2 = ttk.Button(bar, text='Ping 本网段后刷新', command=lambda: self._arp_refresh(True))
        b2.pack(side='left', padx=6)
        self.start_buttons.append(b2)
        self.arp_mon_btn = ttk.Button(bar, text='持续监控(变更告警)', command=self._arp_toggle_monitor)
        self.arp_mon_btn.pack(side='left', padx=6)
        cols = ('IP', 'MAC', '厂商', '备注')
        ttk.Button(bar, text='导出', command=lambda: self._export(self.arp_tree, cols)).pack(side='left')
        self.arp_status = ttk.Label(f, text='读取本机 ARP 邻居表；“持续监控”可发现新设备 / MAC 变化（疑似 ARP 欺骗）。双击某个 IP 可监听它发出的广播/组播报文', foreground='#555')
        self.arp_status.pack(fill='x', padx=10, pady=(0, 6))
        wrap, self.arp_tree = self._make_tree(f, cols, (160, 175, 150, 240))
        wrap.pack(fill='both', expand=True, padx=10, pady=6)
        self.arp_tree.tag_configure('new', foreground='#137333')
        self.arp_tree.tag_configure('spoof', foreground='#fff', background='#d93025')
        self.arp_tree.bind('<Double-1>', self._arp_open_listener)
        self.arp_prev = {}
        self.arp_running = False
        self.arp_stop = threading.Event()

    def _arp_scan_once(self):
        rows = arp_table()
        changes = []
        for r in rows:
            prevmac = self.arp_prev.get(r['ip'])
            if prevmac is None:
                r['note'] = '新增' if self.arp_prev else ''
                if self.arp_prev:
                    changes.append('新增 %s (%s)' % (r['ip'], r['mac']))
            elif prevmac != r['mac']:
                r['note'] = '⚠MAC变化(疑似欺骗) 原 %s' % prevmac
                changes.append('MAC变化 %s: %s→%s' % (r['ip'], prevmac, r['mac']))
            else:
                r['note'] = ''
        self.arp_prev = {r['ip']: r['mac'] for r in rows}
        self.q.put({'tab': 'arp', 'type': 'rows', 'rows': rows, 'changes': changes})

    def _arp_refresh(self, fill):
        if self.scanning:
            return
        self._set_scanning(True)
        self.arp_status.configure(text='正在 Ping 本网段填充 ARP...' if fill else '正在读取 ARP 表...')
        threading.Thread(target=self._arp_worker, args=(fill,), daemon=True).start()

    def _arp_worker(self, fill):
        try:
            if fill:
                ip = _local_ip_for('8.8.8.8')
                if ip and '.' in ip:
                    base = ip.rsplit('.', 1)[0]
                    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
                        list(ex.map(lambda i: ping_host('%s.%d' % (base, i), 300), range(1, 255)))
            self._arp_scan_once()
        except Exception as e:
            self.q.put({'tab': 'arp', 'type': 'status', 'text': '出错: %s' % e})
        finally:
            self.q.put({'tab': 'arp', 'type': 'done'})

    def _arp_toggle_monitor(self):
        if self.arp_running:
            self.arp_stop.set()
            self.arp_running = False
            self.arp_mon_btn.configure(text='持续监控(变更告警)')
            self.arp_status.configure(text='已停止持续监控')
        else:
            self.arp_stop.clear()
            self.arp_running = True
            self.arp_mon_btn.configure(text='停止持续监控')
            threading.Thread(target=self._arp_monitor_worker, daemon=True).start()

    def _arp_monitor_worker(self):
        while not self.arp_stop.is_set():
            try:
                self._arp_scan_once()
            except Exception:
                pass
            w = 0.0
            while w < 10 and not self.arp_stop.is_set():
                time.sleep(0.5)
                w += 0.5

    def _arp_open_listener(self, event=None):
        """双击 ARP 列表里的 IP：弹出小窗口，监听该 IP 发出的广播/组播报文。"""
        sel = self.arp_tree.selection()
        if not sel:
            return
        ip = self.arp_tree.item(sel[0], 'values')[0]
        win = tk.Toplevel(self.root)
        win.title('广播/组播监听 - %s' % ip)
        win.geometry('720x440')
        top = ttk.Frame(win)
        top.pack(fill='x', padx=8, pady=6)
        ttk.Label(top, text='监听 %s 发出的广播/组播（NetBIOS/mDNS/SSDP/LLMNR/DHCP/WS-Discovery 等）' % ip).pack(side='left')
        only_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text='仅显示该 IP', variable=only_var).pack(side='right', padx=(0, 6))
        txt = tk.Text(win, wrap='none', font=('Consolas', 9))
        txt.pack(fill='both', expand=True, padx=8, pady=(0, 6))
        yscroll = ttk.Scrollbar(txt, orient='vertical', command=txt.yview)
        yscroll.pack(side='right', fill='y')
        txt.configure(yscrollcommand=yscroll.set)
        stop = threading.Event()

        def add(line):
            try:
                txt.insert('end', line)
                txt.see('end')
            except tk.TclError:
                pass

        def worker():
            socks = open_bcast_sockets()
            if not socks:
                self.root.after(0, lambda: add('未能绑定任何广播端口（可能被系统占用或权限不足）。\n'))
                return
            names = ', '.join(sorted({n for _s, _p, n in socks}))
            self.root.after(0, lambda: add('已监听端口：%s\n等待广播报文...\n\n' % names))
            raw = [s for s, _p, _n in socks]
            pmap = {s.fileno(): (p, n) for s, p, n in socks}
            smap = {s.fileno(): s for s, _p, _n in socks}
            try:
                while not stop.is_set():
                    try:
                        rl, _, _ = select.select(raw, [], [], 0.5)
                    except (OSError, ValueError):
                        break
                    for s in rl:
                        try:
                            data, addr = s.recvfrom(4096)
                        except OSError:
                            continue
                        src = addr[0]
                        if only_var.get() and src != ip:
                            continue
                        port, name = pmap.get(s.fileno(), (addr[1], '?'))
                        line = '%s  %-15s :%-5d  [%s]  %4dB  %s\n' % (
                            datetime.now().strftime('%H:%M:%S'), src, port, name,
                            len(data), _ascii_preview(data))
                        self.root.after(0, lambda l=line: add(l))
            finally:
                for s in raw:
                    try:
                        s.close()
                    except OSError:
                        pass

        threading.Thread(target=worker, daemon=True).start()

        def on_close():
            stop.set()
            win.destroy()
        ttk.Button(top, text='关闭', command=on_close).pack(side='right', padx=6)
        win.protocol('WM_DELETE_WINDOW', on_close)

    def _build_feature_index(self):
        life_alias = {
            '个人所得税(月估算)': '个税 所得税 工资 iit',
            '数字→人民币大写': '大写金额 金额大写 rmb 人民币',
            '英文大小写转换': '大小写 uppercase lowercase',
            '亲戚称谓计算': '称呼 辈分 亲属 关系',
            '贷款计算器': '房贷 车贷 月供 按揭',
            '存款利息': '利息 定期',
            '世界时间': '时区 时差 timezone',
            '长度换算(公制/英制)': '米 英尺 英寸 length',
            '数字→人民币大写金额': '大写',
        }
        codec_alias = {
            'MD5': '哈希 hash 摘要', 'SHA1': '哈希 hash', 'SHA256': '哈希 hash', 'SHA512': '哈希 hash',
            '时间戳→日期': 'timestamp', '日期→时间戳': 'timestamp',
            'Hex 十六进制': '16进制', 'JSON 格式化/压缩': '格式化',
        }
        idx = [
            ('主机存活扫描', self.tab_ping, None, '主机存活扫描 ping ip段 存活'),
            ('端口扫描', self.tab_port, None, '端口扫描 tcp udp syn 服务识别 banner 端口'),
            ('路由追踪 + 地理定位', self.tab_trace, None, '路由追踪 traceroute 地理定位 离线地理库 世界地图'),
            ('定时监控 + 变更告警', self.tab_monitor, None, '定时监控 变更告警 邮件 webhook 监控'),
            ('网络诊断', self.tab_diag, None, '网络诊断 dns rdns dns查询 whois cidr http tls mtu ip归属地 ping质量'),
            ('链路质量曲线', self.tab_qmon, None, '链路质量曲线 丢包 时延 抖动'),
            ('ARP 监听', self.tab_arp, None, 'arp 监听 广播 mac 厂商'),
            ('加解密编码', self.tab_pass, None, '加解密编码 密码生成 编码 加密'),
            ('生活 工具箱', self.tab_life, None, '生活 工具箱 计算器 换算'),
        ]
        for _i, (_n, _tid, _d) in enumerate(CODEC_TOOLS):
            dn = '加解密编码 · ' + _n
            idx.append((dn, self.tab_pass, ('codec', _i), (dn + ' ' + codec_alias.get(_n, '')).lower()))
        for _i, _d in enumerate(LIFE_TOOLS):
            nm = _d['name']
            dn = '生活 · ' + nm
            idx.append((dn, self.tab_life, ('life', _i), (dn + ' ' + life_alias.get(nm, '')).lower()))
        self._feat_index = idx
        try:
            self._feat_cb['values'] = [e[0] for e in idx]
        except Exception:
            pass

    def _feat_filter(self, event=None):
        if event is not None and getattr(event, 'keysym', '') in ('Return', 'Up', 'Down', 'Escape'):
            return
        q = self._feat_cb.get().strip().lower()
        idx = getattr(self, '_feat_index', [])
        self._feat_cb['values'] = ([e[0] for e in idx if q in e[3] or q in e[0].lower()] if q
                                   else [e[0] for e in idx])

    def _feat_go(self, event=None):
        q = self._feat_cb.get().strip().lower()
        if not q:
            return
        idx = getattr(self, '_feat_index', [])
        hit = ([e for e in idx if q == e[0].lower()]
               or [e for e in idx if q in e[3] or q in e[0].lower()])
        if not hit:
            return
        name, frame, action, kw = hit[0]
        try:
            self.nb.select(frame)
        except Exception:
            pass
        if action:
            kind, i = action
            try:
                if kind == 'codec':
                    self.codec_sel.current(i)
                elif kind == 'life':
                    self.life_sel.current(i)
                    self._life_on_select()
            except Exception:
                pass

    def _build_life_tab(self):
        f = self.tab_life
        top = ttk.Frame(f)
        top.pack(fill='x', padx=10, pady=8)
        ttk.Label(top, text='选择工具:').pack(side='left')
        self.life_sel = ttk.Combobox(top, width=24, state='readonly',
                                     values=[d['name'] for d in LIFE_TOOLS])
        self.life_sel.current(0)
        self.life_sel.pack(side='left', padx=6)
        self.life_sel.bind('<<ComboboxSelected>>', self._life_on_select)
        ttk.Button(top, text='计算', style='Accent.TButton', command=self._life_go).pack(side='left', padx=6)
        self.life_form = ttk.Frame(f)
        self.life_form.pack(fill='x', padx=12, pady=8)
        self.life_entries = []
        self.life_out = tk.Text(f, height=12, wrap='word')
        self.life_out.pack(fill='both', expand=True, padx=10, pady=6)
        self._life_on_select()

    def _life_on_select(self, event=None):
        for w in self.life_form.winfo_children():
            w.destroy()
        self.life_entries = []
        d = LIFE_TOOLS[self.life_sel.current()]
        for i, (label, default) in enumerate(d['fields']):
            ttk.Label(self.life_form, text=label + ':').grid(row=i, column=0, sticky='e', padx=4, pady=3)
            e = ttk.Entry(self.life_form, width=32)
            e.insert(0, default)
            e.grid(row=i, column=1, sticky='w', padx=4, pady=3)
            e.bind('<Return>', lambda ev: self._life_go())
            self.life_entries.append(e)

    def _life_go(self):
        d = LIFE_TOOLS[self.life_sel.current()]
        vals = [e.get() for e in self.life_entries]
        try:
            res = d['run'](vals)
        except Exception as ex:
            res = '输入有误：%s' % ex
        self.life_out.delete('1.0', 'end')
        self.life_out.insert('1.0', '【%s】\n%s' % (d['name'], res))

    def _codec_go(self, mode):
        tid = self._codec_ids[self.codec_sel.current()]
        text = self.codec_in.get('1.0', 'end').rstrip('\n')
        try:
            out = codec_run(tid, text, mode)
        except Exception as ex:
            out = '出错：%s' % ex
        self.codec_out.delete('1.0', 'end')
        self.codec_out.insert('1.0', out)

    def _baseconv_go(self):
        try:
            out = base_convert(self.base_val.get(), int(self.base_from.get()), int(self.base_to.get()))
        except Exception as ex:
            out = '出错：%s' % ex
        self.base_res.configure(text='结果: ' + out)

    def _build_pass_tab(self):
        f = self.tab_pass
        pg = ttk.LabelFrame(f, text='密码生成')
        pg.pack(fill='x', padx=10, pady=(8, 4))
        row = ttk.Frame(pg)
        row.pack(fill='x', padx=6, pady=4)
        ttk.Label(row, text='长度:').pack(side='left')
        self.pw_len = ttk.Spinbox(row, from_=4, to=128, width=5)
        self.pw_len.set(16)
        self.pw_len.pack(side='left', padx=(2, 10))
        ttk.Label(row, text='数量:').pack(side='left')
        self.pw_count = ttk.Spinbox(row, from_=1, to=200, width=5)
        self.pw_count.set(5)
        self.pw_count.pack(side='left', padx=(2, 10))
        self.pw_upper = tk.BooleanVar(value=True)
        self.pw_lower = tk.BooleanVar(value=True)
        self.pw_digits = tk.BooleanVar(value=True)
        self.pw_symbols = tk.BooleanVar(value=True)
        self.pw_amb = tk.BooleanVar(value=False)
        for label, var in (('大写', self.pw_upper), ('小写', self.pw_lower),
                           ('数字', self.pw_digits), ('符号', self.pw_symbols),
                           ('避免易混', self.pw_amb)):
            ttk.Checkbutton(row, text=label, variable=var).pack(side='left', padx=(0, 6))
        ttk.Button(row, text='生成', command=self._gen_pw).pack(side='left', padx=(6, 4))
        ttk.Button(row, text='复制', command=self._copy_pw).pack(side='left')
        self.pw_strength = ttk.Label(pg, text='用密码学安全随机数 (secrets) 生成', foreground='#555')
        self.pw_strength.pack(anchor='w', padx=8)
        self.pw_out = tk.Text(pg, height=4)
        self.pw_out.pack(fill='x', padx=8, pady=(2, 6))
        cf = ttk.LabelFrame(f, text='编码 / 加解密')
        cf.pack(fill='both', expand=True, padx=10, pady=4)
        crow = ttk.Frame(cf)
        crow.pack(fill='x', padx=6, pady=4)
        ttk.Label(crow, text='工具:').pack(side='left')
        self._codec_ids = [tid for _n, tid, _d in CODEC_TOOLS]
        self.codec_sel = ttk.Combobox(crow, width=20, state='readonly',
                                      values=[n for n, _t, _d in CODEC_TOOLS])
        self.codec_sel.current(0)
        self.codec_sel.pack(side='left', padx=6)
        ttk.Button(crow, text='编码/加密/计算', command=lambda: self._codec_go('enc')).pack(side='left', padx=4)
        ttk.Button(crow, text='解码', command=lambda: self._codec_go('dec')).pack(side='left')
        ttk.Button(crow, text='清空',
                   command=lambda: (self.codec_in.delete('1.0', 'end'), self.codec_out.delete('1.0', 'end'))).pack(side='left', padx=4)
        io = ttk.Frame(cf)
        io.pack(fill='both', expand=True, padx=6, pady=4)
        ttk.Label(io, text='输入:').grid(row=0, column=0, sticky='w')
        ttk.Label(io, text='输出:').grid(row=0, column=1, sticky='w')
        self.codec_in = tk.Text(io, height=6, width=40, wrap='word')
        self.codec_out = tk.Text(io, height=6, width=40, wrap='word')
        self.codec_in.grid(row=1, column=0, sticky='nsew', padx=(0, 4))
        self.codec_out.grid(row=1, column=1, sticky='nsew', padx=(4, 0))
        io.columnconfigure(0, weight=1)
        io.columnconfigure(1, weight=1)
        io.rowconfigure(1, weight=1)
        self.codec_in.insert('1.0', 'Hello 你好 NetProbe')
        bf = ttk.Frame(cf)
        bf.pack(fill='x', padx=6, pady=(2, 6))
        ttk.Label(bf, text='进制转换  值:').pack(side='left')
        self.base_val = ttk.Entry(bf, width=18)
        self.base_val.insert(0, '255')
        self.base_val.pack(side='left', padx=4)
        ttk.Label(bf, text='从').pack(side='left')
        self.base_from = ttk.Combobox(bf, width=4, state='readonly', values=['2', '8', '10', '16'])
        self.base_from.set('10')
        self.base_from.pack(side='left', padx=2)
        ttk.Label(bf, text='到').pack(side='left')
        self.base_to = ttk.Combobox(bf, width=4, state='readonly', values=['2', '8', '10', '16'])
        self.base_to.set('16')
        self.base_to.pack(side='left', padx=2)
        ttk.Button(bf, text='转换', command=self._baseconv_go).pack(side='left', padx=4)
        self.base_res = ttk.Label(bf, text='结果:', foreground='#137333')
        self.base_res.pack(side='left', padx=6)


    def _gen_pw(self):
        try:
            n = int(float(self.pw_len.get()))
            c = int(float(self.pw_count.get()))
        except Exception:
            n, c = 16, 5
        pws = gen_password(n, upper=self.pw_upper.get(), lower=self.pw_lower.get(),
                           digits=self.pw_digits.get(), symbols=self.pw_symbols.get(),
                           avoid_ambiguous=self.pw_amb.get(), count=c)
        self.pw_out.delete('1.0', 'end')
        self.pw_out.insert('1.0', '\n'.join(pws))
        if pws:
            bits, label = password_strength(pws[0])
            self.pw_strength.configure(text='强度：约 %d bit（%s）' % (bits, label))

    def _copy_pw(self):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.pw_out.get('1.0', 'end').strip())
            self.pw_strength.configure(text='已复制到剪贴板')
        except Exception:
            pass

    # ---------- 通用 ----------
    def _stop(self):
        if self.scanning:
            self.stop_event.set()
            for lbl in (self.ping_status, self.port_status, self.trace_status):
                lbl.configure(text='正在停止...')

    def _clear(self, tree):
        for i in tree.get_children():
            tree.delete(i)

    def _poll_queue(self):
        try:
            while True:
                m = self.q.get_nowait()
                self._handle(m)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    def _handle(self, m):
        tab, typ = m['tab'], m['type']
        if tab == 'ping':
            if typ == 'row':
                r = m['data']
                tag = 'alive' if r['alive'] else 'dead'
                self.ping_tree.insert('', 'end', tags=(tag,), values=(
                    r['ip'], '存活' if r['alive'] else '超时/不通',
                    '%.1f' % r['rtt_ms'] if r['rtt_ms'] is not None else '-',
                    r['ttl'] if r['ttl'] is not None else '-'))
            elif typ == 'prog':
                self.ping_prog.configure(value=m['done'])
                self.ping_status.configure(
                    text='进度 %d/%d ，存活 %d' %
                    (m['done'], self.ping_prog['maximum'], m['alive']))
            elif typ == 'done':
                self._set_scanning(False)
                self.ping_status.configure(
                    text='完成：共 %d 个地址，存活 %d 个' % (m['total'], m['alive']))
        elif tab == 'port':
            if typ == 'maxset':
                self.port_prog.configure(maximum=max(1, m['total']), value=0)
            elif typ == 'status':
                self.port_status.configure(text=m['text'])
            elif typ == 'row':
                r = m['data']
                st = r['state']
                tag = 'risk' if r.get('risk') == '高' else ('open' if st == 'open' else ('maybe' if 'open' in st else 'closed'))
                self.port_tree.insert('', 'end', tags=(tag,), values=(
                    r['ip'], r['port'], r['proto'], st, r['service'], r.get('banner', '')))
            elif typ == 'prog':
                self.port_prog.configure(value=m['done'])
                self.port_status.configure(
                    text='进度 %d/%d ，开放 %d' % (m['done'], m['total'], m['open']))
            elif typ == 'done':
                self._set_scanning(False)
                note = m.get('note')
                self.port_status.configure(
                    text=note or ('扫描完成，发现 %d 个开放端口' % m.get('open', 0)))
        elif tab == 'trace':
            if typ == 'row':
                h = m['data']
                self.trace_results.append(h)
                g = h.get('geo') or {}
                isp = ' / '.join(x for x in (g.get('isp', ''), g.get('org', ''), g.get('asn', '')) if x)
                self.trace_tree.insert('', 'end', values=(
                    h['hop'], h.get('ip') or '*',
                    '%.1f' % h['rtt_ms'] if h.get('rtt_ms') is not None else '-',
                    g.get('country', ''), g.get('region', ''), g.get('city', ''), isp))
            elif typ == 'done':
                self._set_scanning(False)
                self.trace_status.configure(text='路由追踪完成')
            elif typ == 'error':
                self._set_scanning(False)
                self.trace_status.configure(text='出错：' + m['text'])
                messagebox.showerror('路由追踪', m['text'])
        elif tab == 'monitor':
            if typ == 'row':
                self.mon_tree.insert('', 0, tags=(m.get('tag', 'base'),),
                    values=(m['time'], m['kind'], m['target'], m['detail']))
            elif typ == 'status':
                self.mon_status.configure(text=m['text'])
            elif typ == 'alert':
                try:
                    self.root.bell()
                except Exception:
                    pass
                messagebox.showwarning('监控告警',
                    '检测到 %d 项变更：\n\n%s' % (m['count'], '\n'.join(m['lines'])))
            elif typ == 'toast':
                lvl = m.get('level', 'info')
                (messagebox.showwarning if lvl == 'warn' else messagebox.showinfo)(
                    m.get('title', '提示'), m['text'])
            elif typ == 'stopped':
                self.monitoring = False
                self.mon_start_btn.configure(state='normal')
                self.mon_stop_btn.configure(state='disabled')
                self.mon_status.configure(text='监控已停止')
        elif tab == 'diag':
            if typ == 'out':
                self.diag_out.insert('end', m['text'] + '\n' + '-' * 64 + '\n')
                self.diag_out.see('end')
            elif typ == 'done':
                self._set_scanning(False)
                self.diag_status.configure(text='完成')
        elif tab == 'qmon':
            if typ == 'sample':
                self.qmon_data.append(m['rtt'])
                if len(self.qmon_data) > self.qmon_max:
                    self.qmon_data.pop(0)
                st = qmon_stats(self.qmon_data)
                cur = ('%.1f' % m['rtt']) if m['rtt'] is not None else '丢包'
                self.qmon_stats_lbl.configure(
                    text='采样 %d ｜ 丢包 %s%% ｜ 当前 %s ms ｜ avg %s ｜ min %s ｜ max %s ｜ 抖动 %s ms'
                    % (st['n'], st['loss_pct'], cur, st['avg'], st['min'], st['max'], st['jitter']))
                self._draw_qmon()
            elif typ == 'stopped':
                self.qmon_running = False
                self.qmon_start_btn.configure(state='normal')
                self.qmon_stop_btn.configure(state='disabled')
                self.qmon_status.configure(text='已停止')
        elif tab == 'arp':
            if typ == 'rows':
                self._clear(self.arp_tree)
                for r in m['rows']:
                    note = r.get('note', '')
                    tag = 'spoof' if 'MAC变化' in note else ('new' if note == '新增' else '')
                    self.arp_tree.insert('', 'end', tags=(tag,) if tag else (),
                                         values=(r['ip'], r['mac'], r['vendor'], note))
                self.arp_status.configure(text='%d 个邻居 ｜ 本轮变更 %d' % (len(m['rows']), len(m['changes'])))
                if m['changes']:
                    try:
                        self.root.bell()
                    except Exception:
                        pass
            elif typ == 'status':
                self.arp_status.configure(text=m['text'])
            elif typ == 'done':
                self._set_scanning(False)


def main():
    argv = sys.argv[1:]
    if argv and argv[0] not in ('--gui', '-g'):
        sys.exit(run_cli(argv))
    if argv and argv[0] in ('--gui', '-g'):
        argv = argv[1:]
    if not HAS_TK:
        print('本工具的图形界面需要 Tkinter。')
        print('- Windows / macOS 官方 Python 默认自带；')
        print('- Debian/Ubuntu: sudo apt install python3-tk')
        print('- CentOS/RHEL:   sudo yum install python3-tkinter')
        print()
        print('也可用命令行模式，例如：')
        print('  python net_probe.py ping 192.168.1.0/24')
        print('  python net_probe.py scan 10.0.0.1 --ports 1-1024')
        print('  python net_probe.py --help')
        sys.exit(1)
    root = tk.Tk()
    UU889App(root)
    root.mainloop()


if __name__ == '__main__':
    main()
