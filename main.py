import import_module
import merge_module
import analytics_module
import export_module

def main():
    with open('README.md', 'r') as readme_file:
        print(readme_file.read())

    # Просьба ввести ключ VT
    api_key = input("Для продолжения работы введите API ключ VirusTotal: ")
    print("API ключ введен: ", api_key)
    # Шаг 2: совмещение данных для сравнения информации из разных источников
    merged_data = merge_module.merge_data(api_key)

    # Шаг 3: анализ контекста индикатора и заполнение поля threat_level
    analyzed_data = analytics_module.analyze_data(merged_data)

    # Шаг 4: экспорт данных в формате JSONL
    export_module.export_to_jsonl(analyzed_data)

if __name__ == "__main__":
    main()

