import requests
import xml.etree.ElementTree as ET
import nvdlib

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
        results.append((cpe_name, cve_id, description, base_severity))
    
    return results


def main():
    name = input("Enter the name of application: ")
    api_key = '79a87459-16d2-4e8e-952a-f1ee528c59e2'
    
    try:
        r = nvdlib.searchCPE(keywordSearch = name, limit = 2)
        for eachCPE in r:
            print(eachCPE.cpeName)
            cve_data = get_cve_info(eachCPE.cpeName, api_key)
            results = collect_cve_info(eachCPE.cpeName, cve_data)
            print(len(results))
            if results:
                for result in results:
                    print(result)
            else:
                print("No vulnerabilities found for the specified CPE name.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
