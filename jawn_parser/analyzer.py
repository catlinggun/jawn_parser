import sys
from os.path import exists
import xml.etree.ElementTree as ET


def check_scope(name, split_ip):
    # Determine if the scope for the scan is internal or external
    if int(split_ip[0]) == 10:
        scope = '%s_INT' % name
    elif int(split_ip[0]) == 172:
        if int(split_ip[1]) in range(16, 31):
            scope = '%s_INT' % name
        else:
            scope = '%s_EXT' % name
    elif int(split_ip[0]) == 192:
        if int(split_ip[1]) == 168:
            scope = '%s_INT' % name
        else:
            scope = '%s_EXT' % name
    else:
        scope = '%s_EXT' % name
    return scope


def analyze_files(files):
    # Create dict to store info about each file
    file_info = {}
    print(str("[-] Analyzing {} file(s)...").format(len(files)))
    for file_name in files:
        try:
            # Check if file exists, if not then bail
            if exists(file_name):
                # Parse out the XML for analysis
                xml_tree = ET.parse(file_name)
                xml_root = xml_tree.getroot()
                # Check the root tag of each XML tree to determine which type of scan output the file holds.
                if str.find(xml_root.tag, 'nmaprun') != -1:
                    for ip in xml_root.findall('host/address'):
                        split_ip = ip.get('addr').split('.')
                        break
                    nmap_scope = check_scope('Nmap', split_ip)
                    print(str("    [\033[92mNMAP\033[0m]   '{}' is a legit Nmap file.").format(file_name))
                    file_info.update({file_name: nmap_scope})
                elif str.find(xml_root.tag, 'NessusClientData_v2') != -1:
                    for tag in xml_root.findall('Report/ReportHost/HostProperties/tag'):
                        if tag.attrib.get('name') == 'host-ip':
                            split_ip = tag.text.split('.')
                            break
                    nessus_scope = check_scope('Nessus', split_ip)
                    print(str("    [\033[34mNESSUS\033[0m] '{}' is a legit Nessus file.").format(file_name))
                    file_info.update({file_name: nessus_scope})
                elif str.find(xml_root.tag, 'SCAN') != -1:
                    for result in xml_root.findall('IP'):
                        split_ip = result.attrib.get('value').split('.')
                        break
                    qualys_scope = check_scope('Qualys', split_ip)
                    print(str("    [\033[31mQUALYS\033[0m] '{}' is a legit Qualys file.").format(file_name))
                    file_info.update({file_name: qualys_scope})
                elif xml_root.attrib.get('burpVersion') is not None:
                    print(str("    [\033[33mBURP\033[0m] '{}' is a legit Burp file.").format(file_name))
                    file_info.update({file_name: 'Burp'})
                else:
                    # Reject the file if it doesn't contain the correct root XML tags
                    print(str('    [\033[91m!\033[0m] {} is not a Nmap, Nessus, Qualys file.').format(file_name))
            else:
                print(str('    [\033[91m!\033[0m] {} does not exist.').format(file_name))
                continue
        except:
            print(str('    [\033[91m!\033[0m] {} is not an XML file.').format(file_name))
            print(sys.exc_info())
    if len(file_info) != 0:
        return file_info
    else:
        # Kill the process if no valid scan files were entered
        print('[\033[91m!\033[0m] No valid scan output found in the file parameters.\n')
        print('[\033[91m!\033[0m] Quitting...\n')
        sys.exit(0)
