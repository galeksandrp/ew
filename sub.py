from pprint import pprint
from Sublist3r import sublist3r
from error import domain, httpError
import urllib.request, ssl, socket
import json, queue, re, threading, time



def checkURL(name, url, downgrade=False):
    print('[{name}] Testing: {url}'.format(name=name, url=url))
    req = urllib.request.Request(
            url, headers=ua)
    try:
        res = urllib.request.urlopen(req, timeout=10)
    except (ssl.CertificateError):
        return domain.InvalidCert
    except (socket.timeout):
        return domain.Timeout
    except urllib.error.HTTPError as e:
        return httpError[e.code]
    except urllib.error.URLError as e:
        if str(e.reason) == '[Errno 11001] getaddrinfo failed' \
             or str(e.reason) == '[Errno 11002] getaddrinfo failed':
            return domain.DNS
        elif str(e.reason) == '[WinError 10061] 由于目标计算机积极拒绝，无法连接。':
            return domain.Refused
        elif str(e.reason) == 'EOF occurred in violation of protocol (_ssl.c:645)':
            return domain.Reset
        elif str(e.reason) == 'timed out':
            return domain.Timeout
        elif str(e.reason) == '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:645)':
            return domain.InvalidCert
        elif str(e.reason) == '[SSL: UNKNOWN_PROTOCOL] unknown protocol (_ssl.c:645)':
            return domain.UnknownProtocol
        print('Fail: ['+url+'] '+str(e.reason))
        return domain.Other
    except ConnectionResetError:
        return domain.Reset

    if downgrade: return domain.OK

    finalUrl = res.geturl()
    if re.match('^https:\/\/', finalUrl, re.I):
        try: mes = res.read().decode()
        except UnicodeDecodeError:
            print(url+' decode error.')
            return domain.Other
        mcb = re.findall('(http:\/\/[.\w-]+\/[./\w_-]+\.(css|jpe?g|js|web[pm]|png|gif))', mes, re.I)
        if len(mcb) == 0:
            return domain.OK
        else:
            print('[MCB] On URL [{0}]'.format(finalUrl))
            pprint(mcb)
            return domain.MCB
    else:
        print('{0} redirected to {1}'.format(url, finalUrl))
        return domain.Redirect



class myThread(threading.Thread):
    def __init__(self, name, q, qLock, rLock):
        threading.Thread.__init__(self)
        self.name = name
        self._q = q
        self._qLock = qLock
        self._rLock = rLock

    def run(self):
        while not self._q.empty():
            self._qLock.acquire()
            if self._q.empty():
                self._qLock.release()
                time.sleep(5)
            subdomain = self._q.get()
            self._qLock.release()

            result = checkURL(self.name, 'https://'+subdomain)
            if result in [domain.OK, domain.MCB, domain.DNS]:
                self._append(result, subdomain)
            else:
                print('\t[{0}] {1}, Downgrading.'.format(result[0], subdomain))
                downgradeResult = checkURL(self.name, 'http://'+subdomain, downgrade=True)
                if downgradeResult is domain.OK:
                    self._append(result, subdomain)
                else:
                    print('\t\t[Downgrade] http://{} {}. Ign.'.format(subdomain, downgradeResult[0]))
                    self._append(domain.Ign, '{} ({}) ({})'.format(subdomain, result[0], downgradeResult[0]))

    def _append(self, result, subdomain):
        self._rLock.acquire()
        result.append(subdomain)
        self._rLock.release()


ua = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36'}
threadList = ["Thread-1", "Thread-2", "Thread-3", "Thread-4", "Thread-5"]
workQueue = queue.Queue(0)

class Check:
    def __init__(self, subdomains):
        if subdomains == ():
            raise SystemExit('Fail: 0 Subdomain')
        self._subdomains = subdomains
        self._queueLock = threading.Lock()
        self._resultLock = threading.Lock()

    def start(self):
        self._queueLock.acquire()
        for subdomain in subdomains:
            workQueue.put(subdomain)
        self._queueLock.release()

        threads = []
        for tName in threadList:
            thread = myThread(tName, workQueue, self._queueLock, self._resultLock)
            thread.start()
            threads.append(thread)

        for t in threads:
            t.join()
        self.out()

    def out(self):
        print("<!--")
        for row in domain.ProblematicRef:
            try: row[1]
            except IndexError: continue
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
    check = Check(subdomains)
    check.start()
