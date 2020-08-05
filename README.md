# Passive Scanner 

Passive Scaner it script that get a PCAP file and analysis all packets and create a table have open ports and OS using TTL fingerprint.<br /><br />
States column don't has any meaning on TCP<br />
but in UDP<br />
  we have two status:<br />
     1. open : this means the script find a response for this request<br />
     2. open|filtered : No response received on PCAP file<br />
<br /><br />
Output sample


![alt text](https://raw.githubusercontent.com/0xf1f1/second/master/img/Screenshot%20from%202019-02-25%2010-56-00.png)

