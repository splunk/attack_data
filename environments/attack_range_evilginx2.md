# Attack Range
The Attack Range is used to generate datasets for the Attack Data Project. More information about the Attack range can be found [here](https://github.com/splunk/attack_range).  The `attack_range_evilginx2` environment was a one-off customization as described below.

## Machines
This environment consists of a Windows Server 2016 Domain Controller, a Splunk server, and a Kali instance.

The Kali instance ran evilginx2 version 2.3.2 (available [here](https://github.com/kgretzky/evilginx2)) and was configured to perform reverse-proxy MITM phishing for two sites: O365 (`troutlook.phishnet.attackrange.local`) and Amazon (`scamazon.phishnet.attackrange.local`).  The Splunk server ran tinyproxy to allow a browser to connect to the phishing sites and captured DNS traffic for the detection by way of a local Splunk Stream listener.  The Splunk server resolved all DNS via the Windows DC, which included a stub entry pointing to the Kali/evilginx2 instance as authoritative for `.phishnet.attackrange.local`.

## Users
No user-tracking is performed.
