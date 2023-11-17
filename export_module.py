import json

def export_to_jsonl(analyzed_data):
    jsonl_data = []  # creating an empty list for JSON Lines data
    
    for item in analyzed_data:  # for each tuple in the analyzed data list
        json_item = {
            "md5": item[0],
            "sha256": item[1],
            "malware_class": item[2],
            "malware_family": item[3],
            "av_detects": item[4],
            "threat_level": item[5]
        }  # creating a dictionary for the JSON Lines item
        
        jsonl_data.append(json_item)  # adding the JSON Lines item to the list
    
    with open('analyzed_data.jsonl', 'w') as file:  # opening a file for writing
        for json_item in jsonl_data:  # for each JSON Lines item
            file.write(json.dumps(json_item) + '\n')  # writing the JSON Lines item to the file
    
    print("Data exported to analyzed_data.jsonl")  # printing a message after exporting the data
