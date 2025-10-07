# Malware Detection - YARA

Malware Detection & Threat Intelligence - Cyblack.org
<div>
  
  ## Overview
This project focuses on malware detection and threat intelligence using YARA rules and VirusTotal analysis to identify malicious activity on endpoints. By scanning over 30 file hashes through the VirusTotal API, the project identified a ransomware sample — Medusa Locker — with high confidence. Indicators of Compromise (IOCs) such as file hashes, registry entries, and suspicious file names were then used to craft a custom YARA rule for network-wide detection. Additionally, the project outlines effective detection strategies using SIEM and Sysmon event monitoring, as well as practical prevention measures to enhance endpoint security.
</div>


  ## Aim
To detect malicious activity associated with a specific malware on our endpoint with YARA rule.
</div>

<div>

  ## Objectives
* Detect malicious file hash from a random mix of file hashes using VirusTotal API

* Research common IOC's associated with the malware

* Create a YARA rule to detect IOC's associated with the detected malware.
</div>

## Tools Used
<div>

* Kali VM

* VirusTotal
</div>


<div>
  
## Steps 
* Deployed kali Linux Virtual machine
* Set up an account on VirusTotal and obtained an API Key
* Installed python-3 and python-3 request
```
sudo apt update && sudo apt install python3-venv python3-requests -y
```
* Executed the python script below to scan over 30 file hashes on VirusTotal:
  
```
nano check_hashes.py
```
  
</div>


<div>
  
```
import requests

import time

API_KEY = "db04660556ef61c87c3b574c04d459844861d1cb6ad04bca5cf210cd7d036ac0"

hashes = 

["9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e9d1f51c6",
"3d8c9a2b6e7d1f0a5c3b9e8d7f6a2c9b4e3d1f5a7c6e0b9d2f4a3c1e8b7d62f5",
"156335b95ba216456f1ac0894b7b9d6ad95404ac7df447941f21646ca0090673",
"6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e9d1f5a9f2b47e8",
"0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e9d1f5a9f2b4C6d7e8a3f1c5b9d26a4",
"2f6a2c4b8e9d1f5a9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b06f2e4",
"156335b95ba216456f1ac0894b7b9d6ad95404ac7df447946f21646ca0090673",
"7e3f6a2c4b8e9d1f5a9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b05d6",
"5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e9d1f5a9f2b4c6d7e8a3f13d7",
"6a2c4b8e9d1f5a9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e35f1",
"156335b95ba216456f1ac0894b7b9d6ad95404ac7df447948f21646ca0090673",
"8d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e9d1f5a9f2b40e3",
"1f5a9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e97c5",
"156335b95ba216456f1ac0894b7b9d6ad95404ac7df447943f21646ca0090673",
"5c9b0d7e3f6a2c4b8e9d1f5a9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f28a9",
"156335b95ba216456f1ac0894b7b9d6ad95404ac7df447945f21646ca0090673",
"9e9d1f5a9f2b4C6d7e8аЗf1c5b9d2e0f4a7cЗb6e8d1f2a5c9b0d7eЗf6a2c42d8",
"0a9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e9d12f6",
"6c4b8e9d1f5a9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f51b9",
"156335b95ba216456f1ac0894b7b9d6ad95404ac7df447947f21646ca0090673",
"156335b95ba216456f1ac0894b7b9d6ad95404ac7df447944f21646ca0090673",
"7a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e9d1f5a9f2b4c6d72e5",
"1bc0575b3fc6486cb2510dac1ac6ae4889b94a955d3eade53d3ba3a92d133281",
"1d5a9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e94a7",
"5e8d1f2a5c9b0d7e3f6a2c4b8e9d1f5a9f2b4c6d7e8a3f1c5b9d2e0f4a7c34C8",
"1f5a9f2b4C6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e93a7",
"156335b95ba216456f1ac0894b7b9d6ad95404ac7df447942f21646ca0090673",
"9b2e0f4a7c3b6e8d1f2a5c9b0d7e3f6a2c4b8e9d1f5a9f2b4c6d7e8a3f1c58d3",
"7e3f6a2c4b8e9d1f5a9f2b4c6d7e8a3f1c5b9d2e0f4a7c3b6e8d1f2a5c9b05d6",
"6c6d7e8аЗf1c5b9d2e0f4a7c3b6e8d1f2a5c9b0d7eЗf6a2c4b8e9d1f5a9f20f4",
"5b8d1f2a5c9b0d7e3f6a2c4b8e9d1f5a9f2b4C6d7e8a3f1c5b9d2e0f4a7c13e9"
]

for index, file hash in enumerate(hashes):
 url = f"https://ww.virustotal.com/api/v3/files/{file_hash}"
 headers = {"x-apikey": API_KEY}
 response = requests get (url, headers=headers)
 data = response. json)


 if "data" in data and "attributes" in data["data"]:
   stats = data["data" J["attributes" I["last _analysis_stats"]
   vendors = data["data"] ["attributes"] get ("last _analysis_results", (})
  
   if stats["malicious"] > 0:
     detected_by = []
     for vendor, result in vendors. items():
       if result ["category"] = "malicious":
         detected_by-append(f" {vendor}: {result[' result']}")
     print(f"⚠️ {file_hash} is flagged as malicious by:")
     for detection in detected_by:
       print(f" - {detection}")
   else
     print(f"✅ (file_hash} appears clean")
 if (index + 1) % 4 = 0:
   print("⌛ Waiting for 60 seconds to stay within API rate limit...")
   time. sleep ( 60)
```
<p align="center">
Ref 1: Python script for detecting malicious filehash
</p>


```
python3 check_hashes.py
```

</div>


## Scan Result

<img width="1280" height="800" alt="VirtualBox_Kali Linux ARM64_20_09_2025_01_19_06" src="https://github.com/user-attachments/assets/843cf59e-68a5-4ac9-9f77-a8faa9f00d92" />

<p align="center">
Ref 2: Malicious filehash detected
</p>
 

File hash {1bc0575b3fc6486cb2510dac1ac6ae4889b94a955d3eade53d3ba3a92d133281} was reported to be  malicious by several vendors with a confidence level of 63/72 (Very High).  Threat intelligence on the file further confimed this to be a ransomware called **MEDUSA LOCKER** belonging to the Trojan family.

Using the IOC gathered from Threat intelligence, a YARA rule was created to detect the presence of this malware on the host device and across other devices on the local network.

<div>
  
## Detection & Prevention Strategies

### Detection
* Deploy YARA scanning on endpoints to detect strings associated with Medusa Locker based on certain conditions.
* SIEM Investigation - Process creation using command line/powershell or other LOLBins on the host: Windows EventID 4688 or Sysmon ID 1
* SIEM Investigation - File Creation, access, deletion and/or modification - Sysmon ID 11, 23
* SIEM Investigation - Registry key creation and modification: Windows EventID and Sysmon 12,13, 14 for any sign of persistence
  
 ### Prevention
* Restrict use of LOLBins (e.g., PowerShell, cmd.exe)
* Implement file reputation checks
* Harden registry policies and monitor critical keys

</div>

<div>

  ## YARA Rule

Created to YARA rule to detect Medusa Locker on the compromised host and other hosts within the network based on the IOC's including file_hash, suspicious strings, file characteristics and behavioral indicators where application. For this, the following YARA rule was created:
```
import "pe"
rule Losmercy_Medusa_Locker_Ransomware_Detection {
 meta:
   description = "Medusa Locker Ransomware"
   author = "Losmercy"
   date = "2025-09-21"
 strings:
 //SHA-256 Hash
    $file_hash = "1bc0575b3fc6486cb2510dac1ac6ae4889b94a955d3eade53d3ba3a92d133281"
 //Suspicious strings
    
    $filename1 = "medusa.exe" nocase
    $filename2 = "medusa2.exe" nocase
    $filename3 = "medusalocker.exe" nocase
    $filename4 = "kamikadze.exe" nocase
    $filename5 = "svhost.exe" nocase
    $readme = "HOW_TO_RECOVER_DATA.html"
    $imports = "crypt32.dll" nocase
    $imports = "kernel32.dll" nocase
 //Bahavioral Indicators
    $registry_mod = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
    $registry_mod = "HKCU\\SOFTWARE\\Medusa" nocase
    $registry_mod = "EnableLinkedConnections" nocase
    $a = "mutex"
 condition:
   any of them and filesize < 500KB and (pe.imphash() == "9f60a29044a8e334d03f8bd365c64f0d")
}
```

</div>
<p align="center">
Ref 4: YARA rule to detect Medusa Locker Ransomware 
</p>


## Lessons Learned
* Thorough threat intelligence gathering is essential to crafting effective YARA rules that accurately detect malware without generating excessive false positives.

* Leveraging platforms like VirusTotal can significantly speed up malware analysis and help validate suspicious files with high confidence.

* System event monitoring (Sysmon - if available since not every organizations implement it, Powershell logs, Windows Event Logs, Defender logs, among others) plays a critical role in correlating IOC's and detecting malicious activity across endpoints.

## Recommendations
* Automate YARA scans across endpoints with regular IOC updates to keep up with evolving malware variants

* Integrate with SIEM solutions to enable real-time detection and faster incident response.
