# Example hunt queries (Splunk SPL, adapt field names to your data)

Encoded PowerShell:
```
index=sysmon EventCode=1 Image="*\\powershell.exe" (CommandLine="* -enc *" OR CommandLine="*-EncodedCommand*")
| table _time host User ParentImage CommandLine
```
Kerberoasting (many RC4 tickets from one source):
```
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| bin _time span=1m | stats dc(Service_Name) as spns count by _time Client_Address
| where count>=3
```
Brute force then success:
```
index=wineventlog (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as fails count(eval(EventCode=4624)) as wins by Account_Name Source_Network_Address
| where fails>=5 AND wins>=1
```
