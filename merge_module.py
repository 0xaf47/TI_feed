import import_module

def merge_data(api_key):
    malware_bazaar_data = import_module.import_malware_bazaar_data()
    
    if malware_bazaar_data["query_status"] == "ok":
        data = malware_bazaar_data["data"]

        if len(data) > 0:
            data = data[:4]
            # Место переключения количества сэмплов, обрабатываемых далее
            # Необходимо для использования бесплатного API VT с 4 запросами в минуту

            
            results = []
            for item in data:
                sha256_hash = item["sha256_hash"]
                md5_hash = item["md5_hash"]
                signature = item["signature"]
                
                malware_class = None
                if signature:
                    malware_class = import_module.import_apt_etda_data(signature)
                # Временное отключение запросов к VT для экономии тарифа.
                #av_detects = None 
                av_detects = import_module.import_virus_total_data(sha256_hash, api_key)
                results.append((md5_hash, sha256_hash, malware_class, signature, av_detects))
                
            return results
        else:
            return []
    else:
        return []


