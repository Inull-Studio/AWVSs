import requests
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class AWVSS:
    def __init__(self):
        self.header = {
            'X-Auth': '1986ad8c0a5b3df4d7028d5f3c06e936c403f87f35e1f47ebbee06b3188ee0695', 'Content-Type': 'application/json;charset=UTF-8'}

    def getme(self):
        url = 'https://127.0.0.1:3443/api/v1/me'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def getinfo(self):
        url = 'https://127.0.0.1:3443/api/v1/info'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def getworker(self):
        url = 'https://127.0.0.1:3443/api/v1/workers'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def getnotice(self):
        url = 'https://127.0.0.1:3443/api/v1/notifications'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def getstat(self):
        url = 'https://127.0.0.1:3443/api/v1/me/stats'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def gettargets(self, threat: int = None, criticality: int = None):
        url = 'https://127.0.0.1:3443/api/v1/targets'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def addtarget(self, address: str, criticality: int = 10, description: str = ''):
        url = 'https://127.0.0.1:3443/api/v1/targets'
        param = {'address': address, 'criticality': criticality,
                 'description': 'description'}
        r = requests.post(url, headers=self.header,
                          verify=False, data=json.dumps(param))
        print(r.json())

    def deltarget(self, target_id: str):
        url = f'https://127.0.0.1:3443/api/v1/targets/{target_id}'
        r = requests.request('DELETE', url, headers=self.header, verify=False)
        if r.status_code == 204:
            print('OK')

    def scan(self, target_id: str):
        url = f'https://127.0.0.1:3443/api/v1/scans'
        param = {'profile_id': '11111111-1111-1111-1111-111111111111', 'target_id': target_id,
                 'schedule': {'disable': False, 'start_date': None, 'time_sensitive': False}, 'incremental': False}
        r = requests.post(url, headers=self.header,
                          verify=False, data=json.dumps(param))
        if r.status_code == 201:
            print(r.json())


if __name__ == "__main__":
    Scan = AWVSS()
    # Scan.addtarget('https://www.google.com/')
    # Scan.gettargets()
    # Scan.deltarget('a7063428-9dba-49c3-bfbb-8442fd9cf876')
    # Scan.scan('c4e2f08b-6af3-410b-9951-307d2332576e')
