import pandas as pd

def import_malware_bazaar_data():
    # здесь происходит импорт данных из источника Malware Bazaar
    # реализация импорта данных из источника Malware Bazaar
    malware_bazaar_data = pd.read_csv('malware_bazaar_data.csv')
    return malware_bazaar_data

def import_apt_etda_data():
    # здесь происходит импорт данных из источника APT ETDA
    # реализация импорта данных из источника APT ETDA
    apt_etda_data = pd.read_csv('apt_etda_data.csv')
    return apt_etda_data

def import_virus_total_data():
    # здесь происходит импорт данных из источника Virus Total
    # реализация импорта данных из источника Virus Total
    virus_total_data = pd.read_csv('virus_total_data.csv')
    return virus_total_data
