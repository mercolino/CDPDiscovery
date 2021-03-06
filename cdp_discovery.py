import sys
import paramiko
import sqlite3
import re
import dns.resolver as dr
import dns.reversename as rev
import time


#Constants used on the script
#Timeout for ssh connections and buffer receiving
TIMEOUT = 5

class bcolors:
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


def recv_buffer(conn, stop_string):
    """
    Function created to process and get the received data from the ssh connection
    :param conn: The ssh client connection
    :param stop_string: The stop string, basically the string to wait to stop receiving the buffer
    :return: receive_buffer is the buffer received from the ssh command
    """
    receive_buffer = ""
    #Creating the stop string, removing domain from hostname
    m = re.search('(.+?)\.', stop_string)
    if m:
        stop_string = m.group(1) + '#'
    else:
        stop_string = '#'
    i = 0
    while not (stop_string in receive_buffer):
        # Flush the receive buffer
        try:
            receive_buffer += conn.recv(1024).decode('utf-8')
        except Exception as e:
            if type(e).__name__ == 'timeout':
                i += 1
                if i == 2:
                    print(bcolors.FAIL + "***********Timeout receiving buffer..." + bcolors.ENDC)
                    return receive_buffer + '\n***TIMEOUT ERROR***'
            else:
                print(bcolors.FAIL + "***********Problem receiving data from {}...".format(stop_string) + bcolors.ENDC)
                print(bcolors.FAIL + 'Error: {}'.format(e.args[0]) + bcolors.ENDC)
    return receive_buffer


def process_cdp_output(entries_list):
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


def ssh_connect(host, ip, db_conn):
    """
    Fucntion to connect to the devices via SSH
    :param host: Hostname onf the device to connect
    :param ip: IP address of the device to connect
    :param db_conn: Connection to the DB
    :return: The device info is the same dictionary returned by process_cdp_output()
    """
    # Creating the DB Cursor
    cursor = db_conn.cursor()
    # Creating the SSH CLient object
    ssh = paramiko.SSHClient()
    # Do not stop if the ssh key is not in memory
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(bcolors.HEADER + "Connecting to {}({})...".format(host,ip) + bcolors.ENDC)
    # Connecting....
    try:
        ssh.connect(ip, username=sys.argv[2], password=sys.argv[3], timeout=TIMEOUT)
    except Exception as e:
        print(bcolors.FAIL + "*****************Problem Connecting to {}...".format(host) + bcolors.ENDC)
        print(bcolors.FAIL + "*****************Error: {}".format(e.args[0]) + bcolors.ENDC)
        cursor.execute('SELECT count(*) FROM devices WHERE hostname = ?', (host,))
        n = cursor.fetchone()[0]
        # If there is a problem connecting update the database with status 2
        if n != 0:
            cursor.execute('UPDATE devices SET status = 2 WHERE hostname = ?', (host,))
            db_conn.commit()
        return 'problem'
    else:
        # Invoke shell
        remote_conn = ssh.invoke_shell()
        remote_conn.settimeout(TIMEOUT)
        dummy = recv_buffer(remote_conn, host)
        remote_conn.send('terminal length 0\n')
        dummy = recv_buffer(remote_conn, host)
        # Send command show cdp neighbor detail
        remote_conn.send('show cdp neighbor detail\n')
        # Receive data
        output = recv_buffer(remote_conn, host)
        # Convert data to a list of lines
        data = output.split('\r\n')
        # Process list to get all the data from the device entry in cdp
        device_info = process_cdp_output(data)
        remote_conn.send('exit\n')
        ssh.close()
        # Update the DB to status 1 meaning that the device was followed
        cursor.execute('SELECT count(*) FROM devices WHERE hostname = ?', (host,))
        n = cursor.fetchone()[0]
        if n != 0:
            cursor.execute('UPDATE devices SET status = 1 WHERE hostname = ?', (host,))
            db_conn.commit()
        return device_info


def insert_in_devices(conn2, info2):
    """
    Function to insert data to the database in the table devices
    :param conn2: Database Connection
    :param info2: Dictionary with the devices gathered from processing the output of the sh cdp neighbor detail
    :return: NULL
    """
    # Creating Cursor
    c2 = conn2.cursor()
    for device2 in info2:
        # Checking that the host is not already on the DB
        print(bcolors.HEADER + "Checking that {} is not in the DB...".format(info2[device2]['hostname']) + bcolors.ENDC)
        c2.execute('SELECT COUNT(*) FROM devices WHERE hostname = ?', (info2[device2]['hostname'],))
        n = c2.fetchone()[0]
        if n == 0:
            # Inserting the Device on the DB
            print(bcolors.OKGREEN + "Inserting into DEVICES {}...".format(info2[device2]['hostname']) + bcolors.ENDC)
            c2.execute('INSERT INTO devices(hostname, ip_address, platform, capabilities, status)\
             VALUES(?,?,?,?,?)', (info2[device2]['hostname'],
                                  info2[device2]['ip_address'],
                                  info2[device2]['platform'],
                                  info2[device2]['capabilities'],
                                  0))
            conn2.commit()
        else:
            print(bcolors.OKBLUE + "Device {} already exists in the DB...".format(info2[device2]['hostname']) + bcolors.ENDC)


def check_if_in_table(conn2, host2):
    """
    Function to check if a device is already on the Database
    :param conn2: Database Connection
    :param host2: Host to check
    :return: True or False
    """
    # Creating Cursor
    c2 = conn2.cursor()
    print(bcolors.HEADER + "Checking that {} is not in the DB...".format(host2) + bcolors.ENDC)
    c2.execute('SELECT COUNT(*) FROM devices WHERE hostname = ?', (host2,))
    n = c2.fetchone()[0]
    if n == 0:
        print(bcolors.OKBLUE + "Device {} does not exists in the DB...".format(host2) + bcolors.ENDC)
        return False
    else:
        print(bcolors.OKBLUE + "Device {} already exists in the DB...".format(host2) + bcolors.ENDC)
        return True


def ip_or_host(var):
    """
    Function to determine if a string is a hostname or an ip address
    :param var: string to determine the type of address
    :return: address_type: 'ip' for ip address and 'host' for host
    """
    pattern = '^([0-9]*)\.([0-9]*)\.([0-9]*)\.([0-9]*)$'
    r = re.match(pattern, var)

    if r:
        if int(r.group(1)) > 0 and int(r.group(1)) <= 255 and \
            int(r.group(2)) > 0 and int(r.group(2)) <= 255 and \
            int(r.group(3)) > 0 and int(r.group(3)) <= 255 and \
            int(r.group(4)) > 0 and int(r.group(4)) <= 255:

            address_type = 'ip'
        else:
            raise Error('Wrong Format for an ip address!')
    else:
        address_type = 'host'

    return address_type


def help():
    """
    Function for HELP
    :return: NULL
    """
    print(bcolors.BOLD + bcolors.UNDERLINE + "Usage:" + bcolors.ENDC)
    print(bcolors.BOLD + "\tcdp_discovery seed(s)_host(s) username password" + bcolors.ENDC)
    print(bcolors.BOLD + "\t\tseed(s)_host(s): This can be a single host or multiple hosts separated by comma" + bcolors.ENDC)
    print(bcolors.BOLD + "\tcdp_discovery report [tsv|txt]" + bcolors.ENDC)


if __name__ == "__main__":
    start_time = time.time()
    # Check that the call has the right number of parameters
    if len(sys.argv) not in [3, 4]:
        help()
    else:
        # Connect to Devices
        if sys.argv[1] != 'report' and len(sys.argv) == 4:
            # Connecting to the DB
            print(bcolors.HEADER + 'Connecting to the database...' + bcolors.ENDC)
            conn = sqlite3.connect('cdp.db')
            c = conn.cursor()
            # Drop the tables
            print(bcolors.HEADER + 'Droping tables...' + bcolors.ENDC)
            c.execute('DROP TABLE IF EXISTS devices')
            conn.commit()
            # Create the tables
            print(bcolors.HEADER + 'Creating tables...' + bcolors.ENDC)
            c.execute('CREATE TABLE devices (id INTEGER PRIMARY KEY, hostname, ip_address,\
             platform, capabilities, status)')
            #Converting seed host in a list
            seed_host_list = sys.argv[1].split(',')
            #Iterate through the seed host list for multiple seed hosts
            for seed_host in seed_host_list:
                #Strip any whitespaces from the seed host
                seed_host = seed_host.strip()
                #Check if the seed host is not already on the Database
                if not check_if_in_table(conn, seed_host):
                    #Check if the seed value is an ip or a host
                    if ip_or_host(sys.argv[1]) == 'ip':
                        address = sys.argv[1]
                        #Get hostname from  dns
                        host = dr.query(rev.from_address(seed_host), "PTR")[0].to_text()
                        host = host[:host.find('.')]
                    elif ip_or_host(seed_host) == 'host':
                        #If host query the name to return the ip address
                        try:
                            ip_from_host = dr.query(seed_host)
                        except Exception as e:
                            print(bcolors.FAIL + "***********Problem resolving the hostname {}...".format(
                                seed_host) + bcolors.ENDC)
                            continue
                        ip_from_host = ip_from_host[0].address
                        address = ip_from_host
                        host = seed_host
                    # Insert Seed device on the Database
                    insert_in_devices(conn, {1:{'hostname': host,
                                            'ip_address': address,
                                             'platform': 'Seed',
                                             'capabilities': 'Seed'}})
                    # Connect and process the seed device
                    output = ssh_connect(host, address, conn)
                    if output != 'problem':
                        insert_in_devices(conn, output)
                    # Check if there are still devices to connect to
                    c.execute("SELECT COUNT(*) FROM devices WHERE "
                              "status = 0 AND "
                              "(capabilities LIKE '%Router%' OR capabilities LIKE '%Switch%' OR platform LIKE '%AIR%')")
                    no_devices = c.fetchone()[0]
                    # Connect to the rest of the devices
                    while no_devices != 0:
                        # Select the device
                        c.execute("SELECT * FROM devices WHERE "
                              "status = 0 AND "
                              "(capabilities LIKE '%Router%' OR capabilities LIKE '%Switch%' OR platform LIKE '%AIR%')"
                              "LIMIT 1")
                        resp = c.fetchone()
                        hostname = resp[1]
                        ip_address = resp[2]
                        # Connect to device
                        output = ssh_connect(hostname, ip_address, conn)
                        if output != 'problem':
                            # Insert info on DB
                            insert_in_devices(conn, output)
                        # Check again for devices to connect on DB
                        c.execute("SELECT COUNT(*) FROM devices WHERE "
                              "status = 0 AND "
                              "(capabilities LIKE '%Router%' OR capabilities LIKE '%Switch%' OR platform LIKE '%AIR%')")
                        no_devices = c.fetchone()[0]
                        print(bcolors.HEADER + "#########################" + bcolors.ENDC)
                        print(bcolors.HEADER + "# Devices to connect... #" + bcolors.ENDC)
                        print(bcolors.HEADER + "#         {}            #".format(no_devices) + bcolors.ENDC)
                        print(bcolors.HEADER + "#########################" + bcolors.ENDC)
            conn.close()
        elif sys.argv[1] == 'report' and len(sys.argv) == 3:
            # Generate Report
            print(bcolors.HEADER + "Generating Report..." + bcolors.ENDC)
            conn = sqlite3.connect('cdp.db')
            c = conn.cursor()
            # Text Format
            if sys.argv[2] == 'txt':
                f = open('report.txt', 'w')
                try:
                    rows = c.execute("SELECT * FROM devices WHERE "
                                     "capabilities LIKE '%Router%' OR capabilities LIKE '%Switch%' OR capabilities LIKE '%Seed%'")
                except Exception as e:
                    print(bcolors.FAIL + "Error: {}".format(e.args[0]) + bcolors.ENDC)
                    sys.exit(1)
                for row in rows:
                    f.write(row[2] + ' ' + row[1] + ' ssh\n')
                f.close()
                print(bcolors.OKGREEN + "Report generated Successfuly!!!" + bcolors.ENDC)
            # Generate report on Tab separated values format
            elif sys.argv[2] == 'tsv':
                f = open('report.tsv', 'w')
                try:
                    rows = c.execute("SELECT * FROM devices")
                except Exception as e:
                    print(bcolors.FAIL + "Error: {}".format(e.args[0]) + bcolors.ENDC)
                    sys.exit(1)
                for row in rows:
                    f.write(str(row[0]) + '\t' + row[1] + '\t' + row[2] + '\t' + row[3] + '\t' + row[4] + '\n')
                f.close()
                print(bcolors.OKGREEN + "Report generated Successfuly!!!" + bcolors.ENDC)
            else:
                help()
            conn.close()
        else:
            help()
    elapsed_time = time.time() - start_time
    print((bcolors.OKGREEN + "#" * 50 + "\n" + bcolors.ENDC) * 2)
    print(bcolors.OKGREEN + f"Script took {elapsed_time} seconds to run" + bcolors.ENDC)