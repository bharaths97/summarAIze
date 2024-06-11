import requests
import xml.etree.ElementTree as ET
import nvdlib
import pandas as pd
import csv

# Function to get CVE information from NVD API
def get_cve_info(cpe_name, api_key):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'cpeName': cpe_name
    }
    headers = {
        'apiKey': api_key
    }
    response = requests.get(url, params=params, headers=headers)
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response.json()

# Function to collect the CVE information into tuples
def collect_cve_info(cpe_name, cve_data):
    results = []
    
    if 'vulnerabilities' not in cve_data or not cve_data['vulnerabilities']:
        return results
    
    for item in cve_data['vulnerabilities']:
        cve_id = item['cve']['id']
        description = next((desc['value'] for desc in item['cve']['descriptions'] if desc['lang'] == 'en'), 'No description available')
        base_severity = next((metric['cvssData']['baseSeverity'] for metric in item['cve'].get('metrics', {}).get('cvssMetricV31', [])), 'No base severity available')

        if base_severity not in ['HIGH','CRITICAL']:
            continue
        results.append([cpe_name, cve_id, description, base_severity])
    
    return results

def vul_Collater(AppName,PresentIPs,api_key):
    
    try:
        r = nvdlib.searchCPE(keywordSearch = AppName, limit = 2)
        output=pd.DataFrame()
        for eachCPE in r:
            print(eachCPE.cpeName)
            cve_data = get_cve_info(eachCPE.cpeName, api_key)
            results = collect_cve_info(eachCPE.cpeName, cve_data)
            #print(len(results))
        
            if results:
                for result in results:
                    print([AppName]+result+[PresentIPs])
                    new_row=pd.Series([AppName]+result+[PresentIPs])
                    output=pd.concat([output,new_row.to_frame().T], ignore_index=True)
                    break
            else:
                print("No vulnerabilities found for the specified CPE name.")
        return output
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def csv_parser_APP_IP(filename,apiKey):
    fields = []
    rows = []
    filePath="data\\"+filename+".csv"
    print(filePath)
    with open(filePath, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        fields = next(csvreader)
        output = pd.DataFrame()

        for row in csvreader:
            vulData=vul_Collater(row[1]+" "+row[2],row[3],apiKey)
            output = pd.concat([output,vulData], ignore_index=True)
            #print(output)
        
        output.columns=["Appname", "CPE", "cve_id", "description", "base_severity","IPs_Present"]

        output.to_csv('Vulnerability_Report.csv', index=False)

        #return output

def main():
    AppName_CSV = input("Enter the name of App_IP csv : ")
    apiKey=input("Enter the Api key : ")
    csv_parser_APP_IP(AppName_CSV,apiKey)
    

if __name__ == "__main__":
    main()
