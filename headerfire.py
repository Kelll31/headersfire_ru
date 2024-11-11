#!/usr/bin/env python2
#
# Возьмите список веб-сайтов и проверьте их на наличие заголовков любых версий
# Общие заголовки игнорируются, поэтому отображаются только версии или интересные из них
# Сайты с одинаковыми заголовками объединяются в выводе
# Использование: $ ./headerfire.py <целевой файл или домен>
# Целевым файлом может быть nmap или XML-файл servicescan (используйте service detection с XML)
# В противном случае целевой файл может быть обычным текстом, с одной целью в строке
# Также указаны отсутствующие или неправильно настроенные заголовки безопасности
#

import os
import platform
import re
import requests
import sys
import traceback
from xml.dom import minidom
import OpenSSL

class col:
    if sys.stdout.isatty() and platform.system() != "Windows":
        green = '\033[32m'
        blue = '\033[94m'
        red = '\033[31m'
        brown = '\033[33m'
        end = '\033[0m'
    else:  
        green = ""
        blue = ""
        red = ""
        brown = ""
        end = ""


# парсим Nmap XML файл
def xmlparse_nmap(xmldoc):
    hostlist = xmldoc.getElementsByTagName("host")
    for hostNode in hostlist :
        addressNode = hostNode.getElementsByTagName("address")
        host = addressNode[0].attributes["addr"].value
        ports = hostNode.getElementsByTagName("ports")
        try:
            portlist = ports[0].getElementsByTagName("port")
        except:
            continue
        for portNode in portlist:
            protocol = portNode.attributes["protocol"].value
            # Интересует только TCP
            if protocol != "tcp":
                continue
            port = portNode.attributes["portid"].value
            stateNode = portNode.getElementsByTagName("state")
            state = stateNode[0].attributes["state"].value
            serviceNode = portNode.getElementsByTagName("service")
            try:
                service = serviceNode[0].attributes["name"].value
            except:
                continue
            try:
                tunnel = serviceNode[0].attributes["tunnel"].value
            except:
                tunnel = ""

            if state == "open" and service == "http" and port == "80" and tunnel == "":
                target = "http://" + host
            elif state == "open" and service == "http" and tunnel == "":
                target = "http://" + host + ":" + port
            elif state == "open" and service == "http" and port == "443" and tunnel == "ssl":
                target = "https://" + host
            elif state == "open" and service == "http" and tunnel == "ssl":
                target = "https://" + host + ":" + port
            # Если у нас нет служебной информации, просто перехватите http/https на основе порта
            elif state == "open" and port == "80":
                target = "http://" + host
            elif state == "open"  and port == 443:
                target = "https://" + host

            try:
                targets[target] = ""
            except UnboundLocalError:
                pass

# Службы синтаксического анализа могут обрабатывать XML-файл
def xmlparse_servicescan(xmldoc):
    hostlist = xmldoc.getElementsByTagName("host")
    for hostNode in hostlist :
        host = hostNode.attributes["address"].value
        portlist = hostNode.getElementsByTagName("port")
        for portNode in portlist:
            protocol = portNode.attributes["protocol"].value
            # Интересует только TCP
            if protocol != "TCP":
                continue
            port = portNode.attributes["number"].value
            state = portNode.attributes["state"].value
            desc = portNode.attributes["description"].value
            if state == "open" and desc == "HTTP" and port == "80":
                target = "http://" + host
            elif state == "open" and (desc == "HTTP" or desc == "HTTP-ALT"):
                target = "http://" + host + ":" + port
            elif state == "open" and desc == "HTTPS" and port == "443":
                target = "https://" + host
            elif state == "open" and desc == "HTTPS":
                target = "https://" + host + ":" + port

            try:
                targets[target] = ""
            except UnboundLocalError:
                pass

# Парсим цели (xml)
def xmlparse ():
    xmldoc = minidom.parse(sys.argv[1])
    if xmldoc.getElementsByTagName("nmaprun"):
        xmlparse_nmap(xmldoc)
    elif xmldoc.getElementsByTagName("servicescan"):
        xmlparse_servicescan(xmldoc)
    else:
        print(col.red + "Неправильный XML файл" + col.end)
        sys.exit(1)

# Парсим цели (txt)
def txtparse():
    for line in lines:
        if not line.startswith('http'):
            line = "http://" + line
        targets[line.rstrip()] = ""

# Переворачиваем словарь
def reverse_dict(dictionary):
    sorted = {}
    for k, v in dictionary.items ():
        if v:
            if v not in sorted:
                sorted [v] = []
            sorted [v].append (k)
    return sorted

# Усечение строки до 80 символов
def trunc(string):
    return (string[:75] + '[...]') if len(string) > 80 else string

# Проверьте, нет ли отсутствующих/некорректных заголовков безопасности
def check_security_headers(target, headers):
    # X-Frame-Options
    try:
        m = re.search("SAMEORIGIN|DENY", headers["x-frame-options"], re.IGNORECASE)
        if not m:
            badheaders[target] += "x-frame-options: " + trunc(headers["x-frame-options"]) +"\n"
    except Exception as e:
        missingsecurity[target] += "x-frame-options\n"

    # X-Content-Type-Options: nosniff
    try:
        m = re.search("nosniff", headers["x-content-type-options"], re.IGNORECASE)
        if not m:
            badheaders[target] += "x-content-type-options\n"
    except:
        missingsecurity[target] += "x-content-type-options\n"

    # X-XSS-Protection
    try:
        m = re.search("0", headers["x-xss-protection"], re.IGNORECASE)
        if m:
            badheaders[target] += "x-xss-protection: " + trunc(headers["x-xss-protection"]) + "\n"
    except:
        pass

    # Strict-Transport-Security (HSTS)
    try:
        m = re.search("max-age=(\d+)", headers["strict-transport-security"], re.IGNORECASE)
        if int(m.group(1)) < (60*60*24 * 30):     # Flag if less than 30 days
            badheaders[target] += "strict-transport-security: " + trunc(headers["strict-transport-security"]) +"\n"
    except:
        missingsecurity[target] += "strict-transport-security\n"

    # Access-Control-Allow-Origin (CORS)
    try:
        m = re.search("\*", headers["access-control-allow-origin"], re.IGNORECASE)
        if m:
            badheaders[target] += "access-control-allow-origin: " + trunc(headers["access-control-allow-origin"]) +"\n"
    except:
        pass

    # Content-Security-Policy
    if not ("content-security-policy" in headers or "x-content-security-policy" in headers or "x-webkit-csp" in headers):
        missingsecurity[target] += "content-security-policy\n"


# Выводим хедеры
def print_headers(headerarray):
    for headers,servers in headerarray.items():
       if not headers:
           continue
       for server in servers:
           print(col.blue + server + col.end)
       print(headers)


########
# Main #
########

# предупреждение по сертификатам
requests.packages.urllib3.disable_warnings()
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Получаем цели
targets = {}
try:
    arg = sys.argv[1]
except:
    print("\nUsage: $ " + sys.argv[0] + " <файл или адрес>\n")
    sys.exit(1)

if arg == "-h" or arg == "--help":
    print("\nUsage: $ " + sys.argv[0] + " <файл или адрес>\n")
    sys.exit(1)

if arg.startswith("http"):
    targets[arg] = ""
else:
    try:
        with open(sys.argv[1]) as f:
            lines = f.readlines()
    except:
        print("\nНе могу открыть файл " + arg)
        sys.exit(1)

# Анализируем целевой файл на основе расширения
    if sys.argv[1].endswith("xml"):
        xmlparse()
    else:
        txtparse()

# Получаем список хедеров
try:
    path = os.path.dirname(os.path.realpath(__file__)) + "/headers.txt"
    boringheaders = []
    with open(path, "r") as f:
        lines = f.readlines()
        for line in lines:
            boringheaders.append(line.rstrip().lower())
except IOError:
    print("Фаил headers.txt не найден")
    sys.exit(1)


# Сканируем серверы
headersfound = targets.copy()
missingsecurity = targets.copy()
badheaders = targets.copy()
for target in headersfound:
    if sys.stdout.isatty():
        sys.stdout.write(target + "                                        \r")
        sys.stdout.flush()
    try:
        # По истечении 2х секунд не поулчилось проверить сертификат SSL
        r = requests.head(target, timeout=2, verify=False)
    except requests.exceptions.RequestException:
        try:
            print("HEAD потерпел неудачу, пытаясь GET")
            r = requests.get(target, timeout=2, verify=False)
        except Exception as e:
            continue
    except requests.exceptions.ReadTimeout:
        print(col.red + target + " таймаут" + col.end)
        continue
    except requests.exceptions.ConnectTimeout:
        print(col.red + target + " таймаут" + col.end)
        continue
    except requests.exceptions.SSLError:
        print(col.red + target + " ошибка SSL " + col.end)
        continue
    except OpenSSL.SSL.ZeroReturnError:
        print(col.red + target + " пустой ответ " + col.end)
        continue
    except KeyboardInterrupt:
        print("\n\nПоймал прерывание с клавиатуры, завершаю работу...")
        print("Результаты на данный момент:\n")
        break
    except:
        print(traceback.format_exc())
        continue

    for header in r.headers:
        if header.lower() not in boringheaders:
            h = (r.headers[header][:75] + '[...]') if len(r.headers[header]) > 80 else r.headers[header]
            headersfound[target] += header + ": " + h + "\n"
    check_security_headers(target, r.headers)

# Избавляемся от всех завершающих символов в TTY
if sys.stdout.isatty():
    sys.stdout.write("                                                         \r")
    sys.stdout.flush()


# Интересные хедеры
sorted = reverse_dict(headersfound)
if len(sorted) > 0:
    print(col.green + 'Интересные хедеры' + col.end)
    print_headers(sorted)

# Отсутствующие заголовки безопасности
sorted = reverse_dict(missingsecurity)
if len(sorted) > 0:
    print('\n' + col.brown + 'Отсутствующие заголовки безопасности' + col.end)
    print_headers(sorted)

# Сомнительные заголовки безопасности
sorted = reverse_dict(badheaders)
if len(sorted) > 0:
    print('\n' + col.red + 'Сомнительные заголовки безопасности' + col.end)
    print_headers(sorted)
