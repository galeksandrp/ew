# pylint: disable=C0111
import re
import ssl
import json
import time
import queue
import socket
import threading
import urllib.request
from pprint import pprint
from Sublist3r import sublist3r
from error import domain, HTTP_ERROR, URL_ERROR

Y = '\033[93m'  # yellow
R = '\033[91m'  # red
W = '\033[0m'   # white

UA = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36'}
THREAD_LIST = ["Thread-1", "Thread-2", "Thread-3", "Thread-4", "Thread-5"]
WORK_QUEUE = queue.Queue(0)
QUEUE_LOCK = threading.Lock()
RESULT_LOCK = threading.Lock()
MCB_PATTERN = r'(http:\/\/[.\w-]+\/[./\w_-]+\.(css|jpe?g|js|web[pm]|png|gif))'


def checkURL(name, url, downgrade=False):
    print('[{name}] Testing: {url}'.format(name=name, url=url))
    req = urllib.request.Request(url, headers=UA)
    try:
        res = urllib.request.urlopen(req, timeout=10)
    except ssl.CertificateError:
        return domain.InvalidCert
    except socket.timeout:
        return domain.Timeout
    except urllib.error.HTTPError as e:
        return HTTP_ERROR[e.code]
    except urllib.error.URLError as e:
        reason = str(e.reason)
        try:
            return URL_ERROR[reason]
        except KeyError:
            print(f'{R}Fail: [{url}] {reason}{W}')
            return domain.Other
    except ConnectionResetError:
        return domain.Reset

    if downgrade:
        return domain.OK

    final_url = res.geturl()
    if re.match(r'^https:\/\/', final_url, re.I):
        try:
            mes = res.read().decode()
        except UnicodeDecodeError:
            print(f'{Y}{url} decode error.{W}')
            return domain.Other

        mcb = re.findall(MCB_PATTERN, mes, re.I)
        if mcb:
            print(f'{Y}[MCB] On URL [{final_url}]{W}')
            pprint(mcb)
            return domain.MCB
        return domain.OK
    else:
        print(f'{url} redirected to {final_url}')
        return domain.Redirect



class myThread(threading.Thread):
    def __init__(self, name):
        super().__init__()
        self.name = name

    def run(self):
        while not WORK_QUEUE.empty():
            QUEUE_LOCK.acquire()
            if WORK_QUEUE.empty():
                QUEUE_LOCK.release()
                time.sleep(5)
            subdomain = WORK_QUEUE.get()
            QUEUE_LOCK.release()

            result = checkURL(self.name, 'https://'+subdomain)
            if result in [domain.OK, domain.MCB, domain.DNS]:
                self._append(result, subdomain)
            else:
                print(f'{Y}[{result[0]}] {subdomain}, Downgrading.{W}')
                downgrade_result = checkURL(self.name, 'http://'+subdomain, downgrade=True)
                if downgrade_result is domain.OK:
                    self._append(result, subdomain)
                else:
                    print(f'{Y}[Downgrade] http://{subdomain} {downgrade_result[0]}. Ign.{W}')
                    self._append(domain.Ign, f'{subdomain} ({result[0]}) ({downgrade_result[0]})')

    def _append(self, result, subdomain):
        RESULT_LOCK.acquire()
        result.append(subdomain)
        RESULT_LOCK.release()

class Check:
    def __init__(self, subdomains):
        if subdomains == ():
            raise SystemExit('Fail: 0 Subdomain')
        self._subdomains = subdomains

    def start(self):
        QUEUE_LOCK.acquire()
        for subdomain in subdomains:
            WORK_QUEUE.put(subdomain)
        QUEUE_LOCK.release()

        threads = []
        for thread_name in THREAD_LIST:
            thread = myThread(thread_name)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()
        self.out()

    def out(self):
        print("<!--")
        for row in domain.ProblematicRef:
            try:
                row[1]
            except IndexError:
                continue

            print('\n\t'+row[0]+':')
            row.remove(row[0])

            for subdomain in sorted(row, key=sublist3r.subdomain_sorting_key):
                print("\t\t- "+subdomain)
        print("-->")

        print('<ruleset name="{0}">'.format(tDomain))
        for row in sorted(domain.OK, key=sublist3r.subdomain_sorting_key):
            print('\t<target host="{0}" />'.format(row))
        print('</ruleset>\n')

if __name__ == '__main__':
    tDomain = input('domain: ')

    print('Checking preloading...')
    preload = json.loads(
        urllib.request.urlopen('https://hstspreload.com/api/v1/status/'+tDomain).read().decode()
    )
    try:
        for browser in ('chrome', 'firefox', 'tor'):
            if preload[browser]['present'] and preload[browser]['include_subdomains']:
                exit('Domain preloaded.')
    except TypeError:
        pass

    subdomains = tuple(
        sublist3r.main(
            domain=tDomain, threads=30, savefile=None,
            ports=None, silent=False, verbose=True,
            enable_bruteforce=False, engines=None
        )
    )
    Check(subdomains).start()
