import asyncio
import aiosqlite
import aiodns
import sys
import re
import netdev
import time

# Constants used on the script
# Timeout for ssh connections and buffer receiving
TIMEOUT = 5


class BColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Error(Exception):
    """Base Class for exceptions in this module"""
    pass


def help_function():
    """
    Function for HELP
    :return: NULL
    """
    print(BColors.BOLD + BColors.UNDERLINE + "Usage:" + BColors.ENDC)
    print(BColors.BOLD + "\tasync_cdp_discovery seed(s)_host(s) username password" + BColors.ENDC)
    print(BColors.BOLD + "\t\tseed(s)_host(s): This can be a single host or multiple hosts separated by comma" + BColors.ENDC)
    print(BColors.BOLD + "\tasync_cdp_discovery report [tsv|txt]" + BColors.ENDC)


async def process_cdp_output(entries_list):
    """
    Function created to process the output of the command  /show cdp neighbor detail/
    :param entries_list: The List with the lines of the received response
    :return: it returns a dictionary like {no_device: {hostname: , ip_address: , platform: , capabilities: }...}
    """
    i = 0
    u = 0
    device = 0
    dict = {}
    for entry in entries_list:
        if re.search('---+', entry):
            device += 1
            # Matching the hostname
            m = re.search('Device ID:\s*(.*)', entries_list[i + 1])
            if m:
                hostname = m.group(1)
            else:
                hostname = 'N/A'
            # Matching the IP Address
            m = re.search('IP\saddress:\s*(.*)\s*', entries_list[i + 3])
            if m:
                ip_address = m.group(1)
            else:
                ip_address = 'N/A'
            # Matching Platform and capabilities
            m = re.search('Platform:\s*(.*),\s*Capabilities:\s*(.*)\s', entries_list[i + 4])
            if m:
                platform = m.group(1)
                capabilities = m.group(2)
            else:
                u += 1
                for l in entries_list[i + u + 4:]:
                    m = re.search('Platform:\s*(.*),\s*Capabilities:\s*(.*)\s', l)
                    if m:
                        platform = m.group(1)
                        capabilities = m.group(2)
                        break
                    else:
                        platform = 'N/A'
                        capabilities = 'N/A'
            dict[device] = {'hostname': hostname,
                            'ip_address': ip_address,
                            'platform': platform,
                            'capabilities': capabilities}
        i += 1
    return dict


async def ssh_connect(host, ip):
    """
    Fucntion to connect to the devices via SSH
    :param host: Hostname onf the device to connect
    :param ip: IP address of the device to connect
    :return: The device info is the same dictionary returned by process_cdp_output()
    """
    # Connecting to the host
    print(BColors.HEADER + "Connecting to {}({})...".format(host, ip) + BColors.ENDC)
    try:
        async with netdev.create(username=sys.argv[2], password=sys.argv[3], host=ip, device_type='cisco_ios', timeout=TIMEOUT) as ios:
            cdp_result = await ios.send_command('show cdp neighbor detail')
    except Exception as e:
        print(BColors.FAIL + "*****************Problem Connecting to {}...".format(host) + BColors.ENDC)
        print(BColors.FAIL + "*****************Error: {}".format(e.args[0]) + BColors.ENDC)
        async with aiosqlite.connect('cdp.db') as conn:
            async with conn.execute('SELECT count(*) FROM devices WHERE hostname = ?', (host,)) as cursor:
                n = await cursor.fetchone()
                n = n[0]
                # If there is a problem connecting update the database with status 2
                if n != 0:
                    await conn.execute('UPDATE devices SET status = 2 WHERE hostname = ?', (host,))
                    await conn.commit()
        return
    data = cdp_result.split('\n')
    device_info = await process_cdp_output(data)
    # Update the DB to status 1 meaning that the device was followed
    async with aiosqlite.connect('cdp.db') as conn:
        async with conn.execute('SELECT count(*) FROM devices WHERE hostname = ?', (host,)) as cursor:
            n = await cursor.fetchone()
            n = n[0]
        if n != 0:
            await conn.execute('UPDATE devices SET status = 1 WHERE hostname = ?', (host,))
            await conn.commit()
    await insert_in_devices(device_info)
    return


async def create_db():
    """
    Function to create the DB
    :return: N/A
    """
    print(BColors.HEADER + 'Connecting to the database...' + BColors.ENDC)
    async with aiosqlite.connect('cdp.db') as conn:
        # Drop the tables
        print(BColors.HEADER + 'Droping tables...' + BColors.ENDC)
        await conn.execute('DROP TABLE IF EXISTS devices')
        await conn.commit()
        # Create the tables
        print(BColors.HEADER + 'Creating tables...' + BColors.ENDC)
        await conn.execute('CREATE TABLE devices (id INTEGER PRIMARY KEY, hostname, ip_address, platform, capabilities, status)')


async def check_if_in_table(host2):
    """
    Function to check if a device is already on the Database
    :param host2: Host to check
    :return: True or False
    """
    print(BColors.HEADER + 'Connecting to the database to check if host is in DB...' + BColors.ENDC)
    async with aiosqlite.connect('cdp.db') as conn:
        print(BColors.HEADER + f"Checking that {host2} is not in the DB..." + BColors.ENDC)
        async with conn.execute('SELECT COUNT(*) FROM devices WHERE hostname = ?', (host2,)) as cursor:
            n = await cursor.fetchone()
            n = n[0]
            if n == 0:
                print(BColors.OKBLUE + "Device {} does not exists in the DB...".format(host2) + BColors.ENDC)
                return False
            else:
                print(BColors.OKBLUE + "Device {} already exists in the DB...".format(host2) + BColors.ENDC)
                return True


async def insert_in_devices(info2):
    """
    Function to insert data to the database in the table devices
    :param info2: Dictionary with the devices gathered from processing the output of the sh cdp neighbor detail
    :return: NULL
    """
    print(BColors.HEADER + 'Connecting to the database to insert devices in DB...' + BColors.ENDC)
    async with aiosqlite.connect('cdp.db') as conn:
        for device2 in info2:
            # Checking that the host is not already on the DB
            print(BColors.HEADER + f"Checking that {info2[device2]['hostname']} is not in the DB..." + BColors.ENDC)
            async with conn.execute('SELECT COUNT(*) FROM devices WHERE hostname = ?', (info2[device2]['hostname'],)) as cursor:
                n = await cursor.fetchone()
                n = n[0]
                if n == 0:
                    # Inserting the Device in the DB
                    print(BColors.OKGREEN + f"Inserting into DEVICES {info2[device2]['hostname']}..." + BColors.ENDC)
                    await conn.execute('INSERT INTO devices(hostname, ip_address, platform, capabilities, status)\
                         VALUES(?,?,?,?,?)', (info2[device2]['hostname'],
                                              info2[device2]['ip_address'],
                                              info2[device2]['platform'],
                                              info2[device2]['capabilities'],
                                              0))
                    await conn.commit()
                else:
                    print(BColors.OKBLUE + "Device {} already exists in the DB...".format(info2[device2]['hostname']) + BColors.ENDC)


def ip_or_host(var):
    """
    Function to determine if a string is a hostname or an ip address
    :param var: string to determine the type of address
    :return: address_type: 'ip' for ip address and 'host' for host
    """
    pattern = '^([0-9]*)\.([0-9]*)\.([0-9]*)\.([0-9]*)$'
    r = re.match(pattern, var)

    if r:
        if (0 < int(r.group(1)) <= 255) and (0 < int(r.group(2)) <= 255) and (0 < int(r.group(3)) <= 255) and (0 < int(r.group(4)) <= 255):
            address_type = 'ip'
        else:
            raise Error('Wrong Format for an ip address!')
    else:
        address_type = 'host'

    return address_type


async def run():
    # Creating db_tasks
    print(BColors.HEADER + 'Starting create_db task...' + BColors.ENDC)
    await loop.create_task(create_db())
    # Converting seed host in a list
    seed_host_list = sys.argv[1].split(',')
    # Iterate through the seed host list for multiple seed hosts
    for seed_host in seed_host_list:
        # Strip any whitespaces from the seed host
        seed_host = seed_host.strip()
        # Check if the seed host is not already in the Database
        if not await check_if_in_table(seed_host):
            # Check if the seed value is an ip or a host
            if ip_or_host(sys.argv[1]) == 'ip':
                address = sys.argv[1]
                # Get hostname from  dns
                try:
                    host = await resolver.gethostbyaddr(address)
                except aiodns.error.DNSError:
                    print(BColors.FAIL + f'***********Problem resolving the ip {address}...' + BColors.ENDC)
            elif ip_or_host(seed_host) == 'host':
                # If host query the name to return the ip address
                try:
                    ip_from_host = await resolver.query(seed_host, 'A')
                except Exception as e:
                    print(BColors.FAIL + f"***********Problem resolving the hostname {seed_host}..." + BColors.ENDC)
                    continue
                ip_from_host = ip_from_host[0].host
                address = ip_from_host
                host = seed_host
            # Insert Seed device in the Database
            await insert_in_devices({1: {'hostname': host,
                                         'ip_address': address,
                                         'platform': 'Seed',
                                         'capabilities': 'Seed'}})
            # Connect and process the seed device
            output = await ssh_connect(host, address)
            # Check if there are still devices to connect to
            async with aiosqlite.connect('cdp.db') as conn:
                async with conn.execute("SELECT COUNT(*) FROM devices WHERE status = 0 AND "
                                        "(capabilities LIKE '%Router%' OR capabilities LIKE '%Switch%' OR platform LIKE '%AIR%')") as cursor:
                    no_devices = await cursor.fetchone()
                    no_devices = no_devices[0]
            # Connect to the rest of the devices
            while no_devices != 0:
                # Select the devices
                async with aiosqlite.connect('cdp.db') as conn:
                    async with conn.execute("SELECT * FROM devices WHERE status = 0 AND "
                                            "(capabilities LIKE '%Router%' OR capabilities LIKE '%Switch%' OR platform LIKE '%AIR%')") as cursor:
                        resp = await cursor.fetchall()
                # Create a bunch of tasks to connect to devices
                tasks = []
                for r in resp:
                    hostname = r[1]
                    ip_address = r[2]
                    # Connect to device
                    tasks.append(ssh_connect(hostname, ip_address))
                # Await for the coroutine functions
                await asyncio.wait(tasks)
                # Check again for devices to connect on DB
                async with aiosqlite.connect('cdp.db') as conn:
                    async with conn.execute("SELECT COUNT(*) FROM devices WHERE status = 0 AND "
                                            "(capabilities LIKE '%Router%' OR capabilities LIKE '%Switch%' OR platform LIKE '%AIR%')") as cursor:
                        no_devices = await cursor.fetchone()
                        no_devices = no_devices[0]
                print(BColors.HEADER + "#########################" + BColors.ENDC)
                print(BColors.HEADER + "# Devices to connect... #" + BColors.ENDC)
                print(BColors.HEADER + f"#         {no_devices}            #" + BColors.ENDC)
                print(BColors.HEADER + "#########################" + BColors.ENDC)


async def report():
    # Generate Report
    print(BColors.HEADER + "Generating Report..." + BColors.ENDC)
    # Retrieve DB data
    try:
        async with aiosqlite.connect('cdp.db') as conn:
            async with conn.execute("SELECT * FROM devices WHERE "
                                    "capabilities LIKE '%Router%' OR capabilities LIKE '%Switch%' OR capabilities LIKE '%Seed%'") as cursor:
                rows = await cursor.fetchall()
    except Exception as e:
        print(BColors.FAIL + "Error: {}".format(e.args[0]) + BColors.ENDC)
        sys.exit(1)
    # Check File type requested
    if sys.argv[2] == 'txt':
        f = open('report.txt', 'w')
        for row in rows:
            f.write(row[2] + ' ' + row[1] + ' ssh\n')
        f.close()
    elif sys.argv[2] == 'tsv':
        f = open('report.tsv', 'w')
        for row in rows:
            f.write(str(row[0]) + '\t' + row[1] + '\t' + row[2] + '\t' + row[3] + '\t' + row[4] + '\n')
        f.close()
    else:
        help_function()
    print(BColors.OKGREEN + "Report generated Successfully!!!" + BColors.ENDC)
    return


if __name__ == "__main__":
    start_time = time.time()
    # Check that the call has the right number of parameters
    if len(sys.argv) not in [3, 4]:
        help_function()
    else:
        # Connect to Devices
        if sys.argv[1] != 'report' and len(sys.argv) == 4:
            # Creating loop
            print(BColors.HEADER + 'Creating Loop...' + BColors.ENDC)
            loop = asyncio.get_event_loop()
            resolver = aiodns.DNSResolver(loop=loop)
            loop.run_until_complete(run())
        elif sys.argv[1] == 'report' and len(sys.argv) == 3:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(report())
        else:
            help_function()
    elapsed_time = time.time() - start_time
    print((BColors.OKGREEN + "#" * 50 + "\n" + BColors.ENDC) * 2)
    print(BColors.OKGREEN + f"Script took {elapsed_time} seconds to run" + BColors.ENDC)
