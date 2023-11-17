import import_module
import merge_module
import analytics_module
import export_module

def main():
    # Шаг 1: импорт данных из источников
    malware_bazaar_data = import_module.import_malware_bazaar_data()
    apt_etda_data = import_module.import_apt_etda_data()
    virus_total_data = import_module.import_virus_total_data()

    # Шаг 2: совмещение данных для сравнения информации из разных источников
    merged_data = merge_module.merge_data(malware_bazaar_data, apt_etda_data, virus_total_data)

    # Шаг 3: анализ контекста индикатора и заполнение поля threat_level
    analyzed_data = analytics_module.analyze_data(merged_data)

    # Шаг 4: экспорт данных в формате JSONL
    export_module.export_to_jsonl(analyzed_data)

if __name__ == "__main__":
    main()

