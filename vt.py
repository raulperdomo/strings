import requests
with open("vtAPI.key", 'r') as keyfile:
    key = keyfile.readline()

def VTreport(SHA1sum):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': key, 'resource': SHA1sum}

    response = requests.get(url, params=params)

    return response.json()