## Want an in depth breakdown of these log formats and the KQL? [Check out this free article](#code)




# 1 Firewall Message in 4 Log Formats and Parsing KQL
## JSON:
```json
{
    "Version": "CEF:0",
    "Vendor": "Palo Alto Networks",
    "DeviceProduct": "PAN-OS",
    "DeviceVersion": "9.0",
    "DeviceEventClassId": "10001",
    "Name": "TRAFFIC",
    "Severity": "5",
    "src": "192.168.10.10",
    "dst": "192.168.20.20",
    "spt": "443",
    "dpt": "80",
    "proto": "TCP",
    "cat": "local_website",
    "act": "ALLOW",
    "msg": "Allowed traffic from source to destination"
}
```
```kql
my_table
| extend parse_json(RawData)
| evaluate bag_unpack(RawData)
```

## CEF:
```plaintext
CEF:0|Palo Alto Networks|PAN-OS|9.0|100001|TRAFFIC|5|src=192.168.10.10 dst=192.168.20.20 spt=443 dpt=80 proto=TCP cat=/Security/Application/Firewall act=ALLOW msg=Allowed traffic from source to destination
```
```kql
my_table
// Separate by the | delimiter
| extend SplitData = split(RawData, "|")
// Parse the header from SplitData
| extend
    Version=SplitData[0],
    Vendor=SplitData[1],
    DeviceProduct=SplitData[2],
    DeviceVersion=SplitData[3],
    DeviceEventClassId=SplitData[4],
    Name=SplitData[5],
    Severity=SplitData[6]
// Parse the Key-Value Extensions
| parse-kv SplitData[-1] as (src: string, dst: string, spt: int, dpt: int, proto: string, cat: string, act: string, msg: string) with (pair_delimiter=" ", kv_delimiter="=") 
// Remove un-parsed columns
| project-away SplitData, RawData
```

## BSD Syslog:
```plaintext
<34>Aug 13 12:34:56 edgefirewall01 paloalto[1234]: Allowed local_website traffic from source 192.168.10.10:443 to destination 192.168.20.20:80 using TCP 
```
```kql
my_table
// Extract all the fields available
| parse RawData with "<" Unparsed_PRI:int ">" Unparsed_Month " " Unparsed_Day " " Unparsed_Time " " Hostname " " AppName "[" ProccessId "]" ":" Msg
// Calculate the current year and current month
| extend
    Current_Year=format_datetime(ingestion_time(), "yyyy"),
    Current_Month=format_datetime(ingestion_time(), "M")
// Calculate the log year, accounting for ingestion delay
// Also calculate the severity and facility
| extend Unparsed_Year=iff(toint(Current_Month) < toint(Unparsed_Month), tostring(toint(Current_Year) - 1), Current_Year), Facility=round(Unparsed_PRI/8)
// Put together the datetime field
| extend DateTime=(strcat(Unparsed_Month, " ", Unparsed_Day, " ", Unparsed_Time, " ", Unparsed_Year)), Severity=Unparsed_PRI-(Facility*8)
// Get rid of unparsed content and put DateTime first
| project-away RawData, Unparsed_*, Current_*
| project-reorder DateTime
```

## Syslog RFC 5424:
```plaintext
<165>1 2024-08-12T12:34:56.789Z edgefirewall01 paloalto 1234 ID47 [connection@32473 src="192.168.10.10" dst="192.168.20.20" spt="443" dpt="80" proto="TCP" cat="local_website" act="ALLOW"][protocol@32473 class="TCP"] Allowed traffic from source to destination
```
```kql
my_table
// Extract all fields available
| parse RawData with "<" Unparsed_PRI: int ">" Version " " DateTime: datetime " " Hostname " " AppName " " ProcessId " " EventId "[" * " " Unparsed_ConnectionEvent "][" * " " Unparsed_ProtocolEvent "] " Msg
// Parse structured data key-value pairs
| parse-kv Unparsed_ConnectionEvent as (src: string, dst: string, spt: string, dpt: string, proto: string, cat: string, act: string) with (pair_delimiter=" ", kv_delimiter="=")
| parse-kv Unparsed_ProtocolEvent as (protocol: string)  with (pair_delimiter=" ", kv_delimiter="=")
// Calculate facility and severity from PRI
| extend Facility=round(toint(Unparsed_PRI) / 8)
| extend Severity=Unparsed_PRI - (Facility* 8)
// Get rid of unparsed content
| project-away RawData, Unparsed_*, Current_*  
```
