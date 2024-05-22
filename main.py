import pandas as pd
import requests
import json
from requests.auth import HTTPBasicAuth
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

# API Keys for VirusTota, FraudGuard and AbuseIPDB
vt_api = "INSERT-API-KEY-HERE"
fg_api_user = 'INSERT-API-KEY-HERE'
fg_api_pass = 'INSERT-API-KEY-HERE'
abipdb_api = 'INSERT-API-KEY-HERE'


def load_ip_from_file():
    file_path = filedialog.askopenfilename(title="Select CSV file", filetypes=[("CSV files", "*.csv")])
    if file_path:
        ip_list = pd.read_csv(file_path, index_col=False)
        return ip_list[ip_list.columns[0]].tolist()
    else:
        return []

def load_ip_from_input(root):
    root.deiconify()  # Show the main window for input
    ip_address = simpledialog.askstring("Input", "Enter the IP address:", parent=root)
    root.withdraw()  # Hide the main window again
    return [ip_address]

def center_window(root):
    # Get the screen width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Set the dimensions of the window
    width = 300
    height = 100

    # Calculate the x and y coordinates to center the window
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)

    root.geometry(f'{width}x{height}+{x}+{y}')


def main():
    root = tk.Tk()
    center_window(root)  # Center the main window
    root.withdraw()  # Hides the main window

    choice = tk.messagebox.askyesno("Select IP", "Load IP list from csv file? Press 'No' for analysis of single IP")

    if choice:
        ip_list = load_ip_from_file()
    else:
        ip_list = load_ip_from_input(root)


    # Define global lists
    blacklisted_virus_total = []
    blacklisted_fraud_guard = []
    blacklisted_abuseipdb = []

    # VirusTotal
    def check_virus_total(value):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"

        headers = {
            "accept": "application/json",
            "x-apikey": vt_api
        }

        response = requests.get(url, headers=headers)

        bytes_class = response.__dict__["_content"]
        data_dict = json.loads(bytes_class.decode('utf-8'))
        try:
            analysis_stats = data_dict['data']['attributes']['last_analysis_stats']
            as_owner = data_dict['data']['attributes'].get('as_owner', '-')
            blacklisted_virus_total.append(
                f"{value}, malicious score: {analysis_stats['malicious']}, "
                f"suspicious score: {analysis_stats['suspicious']}, "
                f"as_owner: {as_owner}")
        except KeyError as e:
            print(f'Missing key {e} in the data for {value} IP')

        except json.JSONDecodeError:
            print(f'Could not decode JSON response for {value} IP')
        except Exception as e:
            print(f'Something wrong with {value} IP: {e}')


    # FraudGuard
    api_username = fg_api_user
    password_check_api = fg_api_pass

    def check_fraud_guard(ip):
        api_calls = requests.post('https://rest.fraudguard.io/api/bulk_lookup', json=[ip], verify=True,
                                  auth=HTTPBasicAuth(api_username, password_check_api)).json()
        for api_stat in api_calls:
            country = api_stat["country"]
            risk_level = api_stat['risk_level']
            return f"{ip}, Country: {country}, Risk level: {risk_level}"

    # AbuseIPDB
    def check_abuseipdb(ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': str(ip),
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': abipdb_api
        }

        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            decodedResponse = json.loads(response.text)
            ipAddress = decodedResponse['data']['ipAddress']
            isTor = decodedResponse['data']['isTor']
            isWhitelisted = decodedResponse['data']['isWhitelisted']
            abuseConfidenceScore = decodedResponse['data']['abuseConfidenceScore']
            country_code = decodedResponse['data']['countryCode']
            total_reports = decodedResponse['data']["totalReports"]

            result = f"IP: {ipAddress}, Total Reports: {total_reports}, Abuse Confidence Score: {abuseConfidenceScore}, Country code: {country_code}, is Tor: {isTor}, is Whitelisted: {isWhitelisted}"
            return result

        except Exception as e:
            print(f"Error with IP {ip}: {e}")
            return None

    # Main integration
    results = "Results of IP analysis:\n"

    for ip in ip_list:
        result_virus_total = check_virus_total(ip)
        result_fraud_guard = check_fraud_guard(ip)
        result_abuseipdb = check_abuseipdb(ip)

        if result_virus_total:
            blacklisted_virus_total.append(result_virus_total)
        if result_fraud_guard:
            blacklisted_fraud_guard.append(result_fraud_guard)
        if result_abuseipdb:
            blacklisted_abuseipdb.append(result_abuseipdb)

    # Chain of results
    results += "\nResults from VirusTotal:\n"
    for res in blacklisted_virus_total:
        results += res + "\n"

    results += "\nResults from FraudGuard:\n"
    for res in blacklisted_fraud_guard:
        results += res + "\n"

    results += "\nResults from AbuseIPDB:\n"
    for res in blacklisted_abuseipdb:
        results += res + "\n"

    # Show results in messagebox
    messagebox.showinfo("Results", results, parent=root)

    # Save results to file
    with open("results.txt", "w") as file:
        file.write(results)

if __name__ == "__main__":
    main()
