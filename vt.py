import requests, os, sys


def VTreport(SHA1sum):
    
    with open(os.path.join(sys.path[0], "vtAPI.key"), 'r') as keyfile:
        key = keyfile.readline()
    
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': key, 'resource': SHA1sum}

    response = requests.get(url, params=params)

    return response.json()