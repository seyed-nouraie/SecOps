### Want to collect Aux Logs with the AMA? 

Currently the only way that's supported is through custom logs. Here's what you need to do:

- Deploy a custom table via the API
- Deploy a DCE and DCR with the filepath you want to collect
- And deploy the DCR to servers that have your logs

Once you have your logs, they will show up in the custom table with 2 columns. Datetime and RawData. 

You will probably want to parse that RawData. I wrote a sample KQL query for parsing Palo Alto Firewall logs.

Once you have that configured, here's how you set up summary rules:
