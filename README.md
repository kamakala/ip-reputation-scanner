# ip-reputation-scanner
Relieving the manual task of checking the ip reputation

For now, API calls are made to VirusTotal, FraudGuard and AbuseIPDB. In all those places you can get API key for free (but with daily / monthly limits)

Run script, select IP list from csv or insert single IP. Results are displayed and saved to the file.

### Usage

Register on the VirusTotal, FraudGuard and AbuseIPDB sites, get the API keys and paste them into the code

### Exemplary result for single IP


![image](https://github.com/kamakala/ip-reputation-scanner/assets/79987410/4e0c4692-c676-4816-9f33-2e0e599bac28)

Tested on python 3.11
(first version, probably could be written better)
