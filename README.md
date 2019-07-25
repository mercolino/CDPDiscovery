# CDPDiscovery

Script to discover a network using CDP, it requires SQLite3 installed and paramiko library.

**Usage:**
cdp_discovery.py Seed(s)_Host(s) username password
cdp_discovery.py report [tsv|txt]

- **Seed(s)_Host(s)**: Is the first host or hosts used to begin discover the network, it could be a hostname, ip address or a combination of hosts and ip address in a comma separated list
    - **i.e.** 10.10.10.1
    - **i.e.** host.domain.com
    - **i.e.** 10.10.10.1,host1.domain.com,host2.domain.com,10.10.10.100
- **username and password**: are the credential to connect to each device

If you want to generate a report use the command report and you could choose between two formats:

- **txt**: Where just a list with the format hostname ip_address ssh is generated (Format taht can be used with my script Config Replicator), the only devices shown are switches, routers and WAP's

- **tsv**: Generate a list of all the devices found on the network and on a tab separated value that can be imported in excel.

**Note:** This software is provided AS-IS and without any type of guarantee that will work or will discover all the devices on your network. If you use this software you agree that it is you responsbility and i do not have any kind of responsability if something happens with your network.
Also there is support for Python 3