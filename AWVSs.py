import requests
import json
import sys
import os

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class AFormat:
    def __init__(self):
        pass

    @staticmethod
    def targets_to_address(targets: dict):
        return [x['address'] for x in targets['targets']]

    @staticmethod
    def targets_to_id(targets: dict):
        return [x['target_id'] for x in targets['targets']]


class AWVSS:
    def __init__(self, ip: str = '127.0.0.1', port: int = 3443, key=open('awvsAPIkey', 'r').read().replace('\n', '')):
        self.pre_url = f'https://{ip}:{port}'

        self.header = {
            'X-Auth': key, 'Content-Type': 'application/json;charset=UTF-8'}

    def getme(self):
        url = self.pre_url+'/api/v1/me'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def getinfo(self):
        url = self.pre_url+'/api/v1/info'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def getworker(self):
        url = self.pre_url+'/api/v1/workers'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def getnotice(self):
        url = self.pre_url+'/api/v1/notifications'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def getstat(self):
        url = self.pre_url+'/api/v1/me/stats'
        r = requests.get(url, headers=self.header, verify=False)
        print(r.json())

    def gettargets(self, threat: int = None, criticality: int = None):
        url = self.pre_url+'/api/v1/targets'
        r = requests.get(url, headers=self.header, verify=False)
        return r.json()

    def addtarget(self, address: str, description: str = ''):
        url = self.pre_url+'/api/v1/targets/add'
        param = {'groups': [], 'targets': [
            {'address': address, 'description': description}]}
        r = requests.post(url, headers=self.header,
                          verify=False, data=json.dumps(param))
        print(r.json())

    def deltarget(self, target_id: str):
        url = self.pre_url+'/api/v1/targets/{target_id}'
        r = requests.request('DELETE', url, headers=self.header, verify=False)
        if r.status_code == 204:
            print('OK')

    def scan(self, target_id: str):
        url = self.pre_url+'/api/v1/scans'
        param = {'profile_id': '11111111-1111-1111-1111-111111111111', 'target_id': target_id,
                 'schedule': {'disable': False, 'start_date': None, 'time_sensitive': False}, 'incremental': False}
        r = requests.post(url, headers=self.header,
                          verify=False, data=json.dumps(param))
        if r.status_code == 201:
            print(r.json())


if __name__ == "__main__":
    InputFile = sys.argv
    if not os.path.isfile(awvsAPIkey):
        usrapi_key = input('Pls input ur AWVS API-key:')
        open('awvsAPIkey', 'w+').write(usrapi_key)
        os.system('attrib +s +h awvsAPIkey')
    if InputFile == '':
        print('Please Input FileName!')
        exit(1)
    elif InputFile == "delete":
        os.system('attrib -s -h awvsAPIkey|del /s /q awvsAPIkey')
        print('success')
        exit(0)
    if not os.path.isfile(InputFile):
        print('Not This File!')
        exit(1)
    Scan = AWVSS()
    for ip in open(InputFile, 'r'):
        Scan.addtarget(ip.replace('\n', ''))
        targets = Scan.gettargets()
        # targets_address = AFormat.targets_to_address(targets)
        targets_id = AFormat.targets_to_id(targets)
        # print(targets_address)
        # print(targets_id)
        # Scan.deltarget('a7063428-9dba-49c3-bfbb-8442fd9cf876')
        Scan.scan(targets_id)
