#Author: Renaldy Cahya
#Github: https://github.com/Pleasures631
#usage: automate get log multiple report from total virus


import requests
import pandas as pd
import os
from datetime import datetime

# Ganti dengan API key kamu
API_KEY = '8e7cfc84e07e580ae8644c64ebc2d9ac658f88d844b9f25c320bfc779d173670'

# Input banyak IP (pisahkan dengan koma)
ips_input = input("Masukkan IP address (pisahkan dengan koma): ")
ip_list = [ip.strip() for ip in ips_input.split(',') if ip.strip()]

# Kumpulan data hasil analisis semua IP
all_results = []

for ip_address in ip_list:
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = { 'x-apikey': API_KEY }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        stats = data['data']['attributes']['last_analysis_stats']
        owner = data['data']['attributes'].get('as_owner', 'Unknown')
        vendor = data['data']['attributes']['last_analysis_results']

        result = {
            "IP Address": ip_address,
            "Owner": owner,
            "Malicious": f"{stats['malicious']}/{len(vendor)}",
            "Harmless": stats['harmless'],
            "Suspicious": stats['suspicious'],
            "Undetected": stats['undetected'],
            "Timeout": stats['timeout'],
        }
        all_results.append(result)

        print(f"IP {ip_address} berhasil dianalisis.")

    except requests.exceptions.RequestException as e:
        print(f"IP {ip_address} gagal dianalisis: {e}")

# Simpan ke Excel jika ada hasil
if all_results:
    df = pd.DataFrame(all_results)

    # Buat folder Downloads path
    downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
    filename = f'virustotal_multiple_ip_report_{timestamp}.xlsx'
    filepath = os.path.join(downloads_folder, filename)

    df.to_excel(filepath, index=False)
    print(f"\n File Excel berhasil disimpan di: '{filepath}'")
else:
    print("\n Tidak ada data yang berhasil dianalisis.")
