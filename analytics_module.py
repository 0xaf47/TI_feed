import import_module
import merge_module

def analyze_data(data):

    #Очень примерный и приблизительный классификатор угроз 

    threats = {
        "Spam": "LOW",
        "RiskTool": "MEDIUM",
        "Server-Telnet": "MEDIUM",
        "Server-FTP": "MEDIUM",
        "Server-Proxy": "MEDIUM",
        "Server-Web": "MEDIUM",
        "Client-IRC": "MEDIUM",
        "Hoax": "MEDIUM",
        "Client-P2P": "MEDIUM",
        "Client-SMTP": "MEDIUM",
        "Dialer": "MEDIUM",
        "FraudTool": "MEDIUM",
        "Downloader": "MEDIUM", 
        "WebToolbar": "MEDIUM",
        "NetTool": "MEDIUM",
        "PSWTool": "MEDIUM",
        "RemoteAdmin": "MEDIUM",
        "Adware": "MEDIUM",
        "Phishing": "HIGH",
        "HackTool": "HIGH",
        "Flooder": "HIGH",
        "IM-Flooder": "HIGH",
        "SMS-Flooder": "HIGH",
        "Email-Flooder": "HIGH",
        "Spoofer": "HIGH",
        "Constructor": "HIGH",
        "VirTool": "HIGH",
        "DoS": "HIGH",
        "Trojan": "HIGH",
        "Exploit": "HIGH",
        "Trojan-FakeAV": "HIGH",
        "Monitor": "HIGH",
        "Trojan-ArcBomb": "HIGH",
        "Trojan-DDoS": "HIGH",
        "Trojan-Proxy": "HIGH",
        "Trojan-Notifier": "HIGH",
        "Trojan-Clicker": "HIGH",
        "Trojan-Downloader": "HIGH",
        "Trojan-Dropper": "HIGH",
        "Trojan-Ransom": "HIGH",
        "Trojan-Mailfinder": "HIGH",
        "Trojan-Spy": "HIGH",
        "Trojan-IM": "HIGH",
        "Trojan-SMS": "HIGH",
        "Trojan-GameThief": "HIGH",
        "Trojan-PSW": "HIGH",
        "Trojan-Banker": "HIGH",
        "Backdoor": "HIGH",
        "Rootkit": "HIGH",
        "Bootkit": "HIGH",
        "Virus": "HIGH",
        "Worm": "HIGH",
        "IRC-Worm":  "HIGH"
    }
    
    
    
    result = []  # создаем пустой список для результата
    
    for item in data:  # для каждого кортежа в списке данных
        threat_level = None  # начальное значение уровня угрозы
        
        if item[2] is not None:  # если третий элемент кортежа не None
            for word in item[2].split(", "):  # разбиваем строку на слова и проходим по ним
                print(word)
                if word in threats.keys():  # если слово есть в ключах словаря угроз
                    if threat_level is None or threats[word] > threat_level:  # если уровень угрозы пустой или найденный уровень выше текущего
                        threat_level = threats[word]  # обновляем уровень угрозы
        if threat_level is None:  
            threat_level = "undefined"
        result.append(item + (threat_level,))  # добавляем кортеж с уровнем угрозы в список результата
    
    return result  # возвращаем список кортежей с уровнями угроз


