import requests
from bs4 import BeautifulSoup
def import_malware_bazaar_data():
    # здесь происходит импорт данных из источника Malware Bazaar
    url = 'https://mb-api.abuse.ch/api/v1/'
    payload = {'query': 'get_recent', 'selector': '100'}
    response = requests.post(url, data=payload)
    
    if response.status_code == 200:
        malware_bazaar_data = response.json()
        return malware_bazaar_data
    else:
        print('Failed to import data from Malware Bazaar')
        return None

def import_apt_etda_data(tool_name):
    # здесь происходит импорт данных из источника APT ETDA
    url = f'https://apt.etda.or.th/cgi-bin/listtools.cgi?c=&t=&x={tool_name}'
    response = requests.get(url)
    # Отправляем поисковые запросы, находим ссылки на страницы инструмента и берем первую (самая релевантная) 
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a', class_='inlink')
        tool_links = [link['href'] for link in links if "?t=" in link['href']]
        
        if tool_links:
            tool_url = 'https://apt.etda.or.th' + tool_links[0]
            tool_response = requests.get(tool_url)
            # На странице инструмента берем поле Type
            if tool_response.status_code == 200:
                tool_soup = BeautifulSoup(tool_response.content, 'html.parser')
                type_field = tool_soup.find('td', string='Type')
                
                if type_field:
                    return type_field.find_next_sibling().get_text()
                else:
                    return None
            else:
                print('Failed to import data from APT ETDA')
                return None
        else:
            return None
def import_virus_total_data(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    
    response = requests.get(url, headers=headers)
    data = response.json()
    print(data)
 
    
    av_detects = []
    
    for engine, result in data["data"]["attributes"]["last_analysis_results"].items():
        if result["category"] == "malicious" and result["result"] != "null":
            av_detects.append(result["result"])
    
    return av_detects

