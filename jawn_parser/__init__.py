import base64
import sys
import argparse
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from jawn_parser import analyzer
from jawn_parser import database
from jawn_parser import excel


def jawn_parser(client_name, include_info, files):
    try:
        # Define attributes/columns for each scan file to be parsed (changing these will change column order)
        nmap_attribs = (
            'addr', 'hostname', 'MAC', 'Manufacturer', 'state', 'protocol', 'portid', 'name', 'ostype', 'product',
            'version', 'extrainfo', 'scriptinfo')
        nessus_attribs = (
            'host-ip', 'protocol', 'port', 'host-fqdn', 'cvss3_base_score', 'risk_factor', 'pluginName', 'synopsis',
            'description', 'solution', 'plugin_output', 'see_also', 'xref', 'cve', 'operating-system',
            'svc_name')
        qualys_attribs = (
            'IP', 'hostname', 'protocol', 'port', 'CVSS_BASE', 'severity', 'TITLE', 'DIAGNOSIS', 'CONSEQUENCE',
            'SOLUTION', 'RESULT', 'TYPE')
        burp_attribs = (
            'host', 'path', 'ip', 'severity', 'confidence', 'name', 'issueBackground', 'remediationBackground', 'references',
            'vulnerabilityClassifications', 'issueDetail', 'issueDetailItems', 'request', 'response',
            'responseRedirected', 'filename', 'cookies_set')
        findings_count = 0
        # Create sqlite database in memory
        database = create_db('jawn_parser')
        for file, scan_type in files.items():
            # Parse Nmap file
            if str.find(scan_type, 'Nmap') != -1:
                database = create_dbtable(scan_type, nmap_attribs, database)
                port_data = {}
                # Instantiate XML tree for nmap output
                nmap_tree = ET.parse(file)
                nmap_root = nmap_tree.getroot()
                print(str('    [\033[92m+\033[0m] Nmap file {} loaded.').format(file))
                # Find all 'host' items in the xml output
                for host in nmap_root.findall('host'):
                    # Reset all attributes for each line item
                    for i in nmap_attribs:
                        port_data[i] = ''
                    # Extract address (IP and MAC where available) attributes for host
                    for address in host.findall('address'):
                        if address.attrib['addrtype'] == 'ipv4':
                            port_data['addr'] = address.attrib['addr']
                        elif address.attrib['addrtype'] == 'mac':
                            port_data['MAC'] = address.attrib['addr']
                            try:
                                if address.attrib['vendor'] is not None:
                                    port_data['Manufacturer'] = address.attrib['vendor']
                            except KeyError:
                                continue
                        # check if hostname information exists and add to line item
                        if host.find('hostnames/hostname') is not None:
                            port_data['hostname'] = host.find('hostnames/hostname').attrib['name']
                    # see if ports were discovered
                    if len(host.findall('ports/port')) != 0:
                        # Iterate through each open port on host
                        for port in host.findall('ports/port'):
                            if port.find('state').attrib['reason'] != 'no-response':
                                port_data['state'] = port.find('state').attrib['state']
                                for attrib in port.items():
                                    if attrib[0] in nmap_attribs:
                                        port_data[attrib[0]] = attrib[1]
                                for service in port.findall('service'):
                                    for attrib in service.items():
                                        if attrib[0] in nmap_attribs:
                                            port_data[attrib[0]] = attrib[1]
                                if len(port.findall('script')) != 0:
                                    for script in port.findall('script'):
                                        try:
                                            port_data['scriptinfo'] += str(script.attrib['id'].strip() + ':\n')
                                            if len(script.findall('table')) != 0:
                                                for table in script.findall('table'):
                                                    if len(table.findall('table')) != 0:
                                                        for nestedtable in table.findall('table'):
                                                            if len(nestedtable.findall('elem')) != 0:
                                                                if len(table.findall('elem')) != 0:
                                                                    if len(table.attrib) != 0:
                                                                        port_data['scriptinfo'] += str(
                                                                            '\t' + table.attrib['key'].strip() + ':\n')
                                                                        for row in table.findall('elem'):
                                                                            if len(row.attrib) != 0:
                                                                                port_data['scriptinfo'] += str(
                                                                                    '\t' + row.attrib['key'].strip() + ':')
                                                                                port_data['scriptinfo'] += str(
                                                                                    '\t' + row.text.strip())
                                                    if len(table.findall('elem')) != 0:
                                                        #port_data['scriptinfo'] += str('\t' + table.attrib['key'].strip() + ':\n')
                                                        for row in table.findall('elem'):
                                                            if len(row.attrib) != 0:
                                                                port_data['scriptinfo'] += str('\t' + row.attrib['key'].strip() + ':')
                                                                port_data['scriptinfo'] += str('\t' + row.text.strip())
                                            else:
                                                port_data['scriptinfo'] += str(
                                                    '\t' + script.attrib['output'].strip() + '\n')
                                            if len(script.findall('elem')) != 0:
                                                for elem in script.findall('elem'):
                                                    if len(elem.attrib) !=0:
                                                        port_data['scriptinfo'] += str('\t' + elem.attrib['key'].strip() + ':')
                                                        port_data['scriptinfo'] += str('\t' + elem.text.strip() + '\n')
                                            port_data['scriptinfo'] += '\n'
                                        except:
                                            continue
                                insert_dbtable(scan_type, port_data, database)
                                for service_detail in ('product', 'version', 'extrainfo', 'scriptinfo'):
                                        port_data[service_detail] = ''
                    else:
                        insert_dbtable(scan_type, port_data, database)
                continue
            # Parse out Nessus
            elif str.find(scan_type, 'Nessus') != -1:
                database = create_dbtable(scan_type, nessus_attribs, database)
                # Insert all XML data into one object
                nessus_tree = ET.parse(file)
                nessus_root = nessus_tree.getroot()
                print(str('    [\033[92m+\033[0m] Nessus file {} loaded.').format(file))
                for report_host in nessus_root.findall('Report/ReportHost'):
                    # Initialize the dict for the line item being extracted from the nessus XML
                    finding = {}
                    # Get all the host data and populate the initial finding dict
                    for host_properties in report_host.findall('HostProperties/tag'):
                        if host_properties.get('name') in nessus_attribs:
                            finding[host_properties.get('name')] = host_properties.text
                    # Grab all findings for the current host
                    for report_items in report_host.findall('ReportItem'):
                        # Initialize a list to store all the finding keys, so they can be cleared on next iteration
                        line_reset = []
                        # Extract the XML data
                        for attribs in report_items.items():
                            if attribs[0] in nessus_attribs:
                                finding[attribs[0]] = attribs[1]
                                line_reset.append(attribs[0])
                        # Rub the phleeb because it has all the phleeb juice
                        for elements in report_items:
                            if elements.tag in nessus_attribs:
                                finding[elements.tag] = elements.text
                                line_reset.append(elements.tag)
                        # Set a 0 instead of a null value for CVSS for later sorting
                        if 'cvss3_base_score' not in finding or finding['cvss3_base_score'] == '':
                            finding['cvss3_base_score'] = 0
                            line_reset.append('cvss3_base_score')
                        # Insert the finding into the database
                        if finding.get('risk_factor') != 'None' or include_info == True:
                            insert_dbtable(scan_type, finding, database)
                            findings_count += 1
                        # Reset the finding data only (not the host data)
                        for i in line_reset:
                            finding[i] = ''
                continue
            elif str.find(scan_type, 'Qualys') != -1:
                database = create_dbtable(scan_type, qualys_attribs, database)
                qualys_tree = ET.parse(file)
                qualys_root = qualys_tree.getroot()
                print(str('    [\033[92m+\033[0m] Qualys file {} loaded.').format(file))
                for report_host in qualys_root.findall('IP'):
                    finding = {'IP': report_host.get('value')}
                    if report_host.get('name') is not None:
                        finding['hostname'] = report_host.get('name')
                    if len(report_host.findall('VULNS/CAT')) != 0:
                        line_reset = []
                        for values in report_host.findall('VULNS/CAT'):
                            finding['port'] = values.get('port')
                            finding['protocol'] = values.get('protocol')
                            line_reset.append('port')
                            line_reset.append('protocol')
                        for value in report_host.findall('VULNS/CAT/VULN'):
                            finding['TYPE'] = 'Vuln'
                            line_reset.append('TYPE')
                            if (value.get('severity')) is not None:
                                if value.get('severity') == '1':
                                    finding['severity'] = 'None'
                                elif value.get('severity') == '2':
                                    finding['severity'] = 'Low'
                                elif value.get('severity') == '3':
                                    finding['severity'] = 'Medium'
                                elif value.get('severity') == '4':
                                    finding['severity'] = 'High'
                                elif value.get('severity') == '5':
                                    finding['severity'] = 'Critical'
                                line_reset.append('severity')
                            for element in value.iter():
                                if element.tag in qualys_attribs:
                                    finding[element.tag] = element.text
                                    line_reset.append(element.tag)
                            insert_dbtable(scan_type, finding, database)
                            for i in line_reset:
                                finding[i] = ''
                        if len(report_host.findall('PRACTICES/CAT')) != 0:
                            line_reset = []
                            for values in report_host.findall('PRACTICES/CAT'):
                                finding['port'] = values.get('port')
                                finding['protocol'] = values.get('protocol')
                                line_reset.append('port')
                                line_reset.append('protocol')
                            for value in report_host.findall('PRACTICES/CAT/PRACTICE'):
                                finding['TYPE'] = 'Practice'
                                line_reset.append('TYPE')
                                if (value.get('severity')) is not None:
                                    if value.get('severity') == '1':
                                        finding['severity'] = 'None'
                                    elif value.get('severity') == '2':
                                        finding['severity'] = 'Low'
                                    elif value.get('severity') == '3':
                                        finding['severity'] = 'Medium'
                                    elif value.get('severity') == '4':
                                        finding['severity'] = 'High'
                                    elif value.get('severity') == '5':
                                        finding['severity'] = 'Critical'
                                    line_reset.append('severity')
                                for element in value.iter():
                                    if element.tag in qualys_attribs:
                                        finding[element.tag] = element.text
                                        line_reset.append(element.tag)
                                insert_dbtable(scan_type, finding, database)
                                for i in line_reset:
                                    finding[i] = ''
                    if include_info:
                        if len(report_host.findall('INFOS/CAT')) != 0:
                            for value in report_host.findall('INFOS/CAT/INFO'):
                                line_reset = []
                                finding['TYPE'] = 'Informational'
                                line_reset.append('TYPE')
                                finding['severity'] = 'None'
                                line_reset.append('severity')
                                for element in value.iter():
                                    if element.tag in qualys_attribs:
                                        finding[element.tag] = element.text
                                insert_dbtable(scan_type, finding, database)
                                for i in line_reset:
                                    finding[i] = ''
                        if len(report_host.findall('SERVICES/CAT')) != 0:
                            for value in report_host.findall('SERVICES/CAT/SERVICE'):
                                line_reset = []
                                finding['TYPE'] = 'Services'
                                line_reset.append('TYPE')
                                finding['severity'] = 'None'
                                line_reset.append('severity')
                                for element in value.iter():
                                    if element.tag in qualys_attribs:
                                        finding[element.tag] = element.text
                                insert_dbtable(scan_type, finding, database)
                                for i in line_reset:
                                    finding[i] = ''
            # Parse Burp
            elif str.find(scan_type, 'Burp') != -1:
                database = create_dbtable(scan_type, burp_attribs, database)
                finding_data = {}
                cookies = []
                # Instantiate XML tree for nmap output
                burp_tree = ET.parse(file)
                burp_root = burp_tree.getroot()
                # List of details that are HTML encoded
                encoded_details = ['issueBackground', 'remediationBackground', 'references',
                                   'vulnerabilityClassifications', 'issueDetail', 'issueDetailItems']
                # Set up regex to remove HTML tags and encoding from results
                remove_tags = re.compile('<.*?>')
                remove_encoding = re.compile('&quot;')
                unix2dos = re.compile('\r\n')
                print(str('    [\033[32m+\033[0m] Burp file {} loaded.').format(file))
                # Find all 'host' items in the xml output
                for issue in burp_root.findall('issue'):
                    # Reset all attributes for each line item
                    for attribute in burp_attribs:
                        finding_data[attribute] = ''
                    # Extract finding data for each attribute
                    for detail in issue:
                        finding_data['filename'] = file
                        if detail.tag in burp_attribs or detail.tag == 'requestresponse':
                            if detail.tag == 'host':
                                finding_data['host'] = detail.text
                                # finding_data['ip'] = detail.attrib.get('ip')
                            elif detail.tag == 'severity':
                                if detail.text == 'Information':
                                    finding_data[detail.tag] = 'None'
                                else:
                                    finding_data[detail.tag] = detail.text
                            elif detail.tag == 'requestresponse':
                                for packet in detail:
                                    if packet.get("base64") == 'true' and packet.tag != 'responseRedirected':
                                        try:
                                            finding_data[packet.tag] = base64.urlsafe_b64decode(packet.text).decode('utf-8')
                                        except:
                                            finding_data[packet.tag] = str(base64.urlsafe_b64decode(packet.text))
                                    else:
                                        finding_data[packet.tag] = packet.text
                            elif detail.tag in encoded_details:
                                if detail.text is not None:
                                    soup = BeautifulSoup(detail.text, 'html.parser')
                                    finding_data[detail.tag] = soup.get_text()
                                else:
                                    finding_data[detail.tag] = ''
                            else:
                                finding_data[detail.tag] = detail.text
                    insert_dbtable(scan_type, finding_data, database)
            continue
        findings_log = create_xlworkbook(client_name)
        # This is insane but it makes sure the sheets are in proper order when written to the workbook.
        dirty_sheets = []
        clean_sheets = {}
        for name in files.values():
            dirty_sheets.append(name)
        dirty_sheets = list(dict.fromkeys(dirty_sheets))
        # The values in this dict determine the order of the tabs in the final workbook
        all_sheets = {'Nmap_EXT': 1, 'Nessus_EXT': 2, 'Qualys_EXT': 3,
                      'Nmap_INT': 4, 'Nessus_INT': 5, 'Qualys_INT': 6,
                      'Burp': 7}
        for dirty_sheet in dirty_sheets:
            if dirty_sheet in all_sheets:
                clean_sheets.update({all_sheets.get(dirty_sheet): dirty_sheet})
        clean_sheets = clean_sheets.items()
        clean_sheets = sorted(clean_sheets)
        for clean_sheet in clean_sheets:
            if str.find(clean_sheet[1], 'Nmap') != -1:
                database_query = str('SELECT * FROM {}').format(clean_sheet[1])
                data = database.execute(database_query)
                row_count = 1
                for item in data:
                    row_count += 1
                row_iter = 1
                nmap_sheet = create_xlsheet(clean_sheet[1], findings_log, nmap_attribs, row_count)
                create_xltable(nmap_sheet, nmap_attribs, row_count)
                data = database.execute(database_query)
                for row in data:
                    nmap_sheet.write_row(row_iter, 0, row)
                    row_iter += 1
                print(str("    [\033[92mNMAP\033[0m]   '{}' sheet successfully created with {} rows.")
                      .format(clean_sheet[1], row_count))
            if str.find(clean_sheet[1], 'Nessus') != -1:
                database_query = str('SELECT * FROM "{}" ORDER BY CASE risk_factor ' \
                                     'WHEN "Critical" THEN 0 ' \
                                     'WHEN "High" THEN 1 ' \
                                     'WHEN "Medium" THEN 2 ' \
                                     'WHEN "Low" THEN 3 ' \
                                     'WHEN "None" THEN 4 ' \
                                     'END, ' \
                                     'cvss3_base_score DESC,' \
                                     'pluginName ASC').format(clean_sheet[1])
                data = database.execute(database_query)
                row_count = 1
                for item in data:
                    row_count += 1
                row_iter = 1
                nessus_sheet = create_xlsheet(clean_sheet[1], findings_log, nessus_attribs, row_count)
                create_xltable(nessus_sheet, nessus_attribs, row_count)
                data = database.execute(database_query)
                for row in data:
                    nessus_sheet.write_row(row_iter, 0, row)
                    row_iter += 1
                print(str("    [\033[34mNESSUS\033[0m] '{}' sheet successfully created with {} rows.")
                      .format(clean_sheet[1], row_count))
            if str.find(clean_sheet[1], 'Qualys') != -1:
                database_query = str('SELECT * FROM "{}" ORDER BY CASE severity ' \
                                     'WHEN "Critical" THEN 0 ' \
                                     'WHEN "High" THEN 1 ' \
                                     'WHEN "Medium" THEN 2 ' \
                                     'WHEN "Low" THEN 3 ' \
                                     'WHEN "None" THEN 4 ' \
                                     'END, ' \
                                     'TITLE ASC').format(clean_sheet[1])
                data = database.execute(database_query)
                row_count = 1
                for item in data:
                    row_count += 1
                row_iter = 1
                qualys_sheet = create_xlsheet(clean_sheet[1], findings_log, qualys_attribs, row_count)
                create_xltable(qualys_sheet, qualys_attribs, row_count)
                data = database.execute(database_query)
                for row in data:
                    qualys_sheet.write_row(row_iter, 0, row)
                    row_iter += 1
                print(str("    [\033[31mQUALYS\033[0m] '{}' sheet successfully created with {} rows.")
                      .format(clean_sheet[1], row_count))
            if str.find(clean_sheet[1], 'Burp') != -1:
                database_query = str('SELECT * FROM "{}" ORDER BY CASE severity ' \
                                     'WHEN "Critical" THEN 0 ' \
                                     'WHEN "High" THEN 1 ' \
                                     'WHEN "Medium" THEN 2 ' \
                                     'WHEN "Low" THEN 3 ' \
                                     'WHEN "None" THEN 4 ' \
                                     'END, ' \
                                     'name ASC').format(clean_sheet[1])
                data = database.execute(database_query)
                row_count = 1
                for item in data:
                    row_count += 1
                row_iter = 1
                burp_sheet = create_xlsheet(clean_sheet[1], findings_log, burp_attribs, row_count)
                create_xltable(burp_sheet, burp_attribs, row_count)
                data = database.execute(database_query)
                for row in data:
                    burp_sheet.write_row(row_iter, 0, row)
                    row_iter += 1
                print(str("    [\033[33mBURP\033[0m]   '{}' sheet successfully created with {} rows.")
                      .format(clean_sheet[1], row_count))
        findings_log.close()
        print(str("[\033[92m*\033[0m] Results successfully saved to '{}'. Enjoy!\n").format(findings_log.filename))
        database.close()
    except:
        print(sys.exc_info())


def main():
    print("""
       _                                                           
      (_)___ __      ______        ____  ____ ______________  _____
     / / __ `/ | /| / / __ \\      / __ \\/ __ `/ ___/ ___/ _ \\/ ___/
    / / /_/ /| |/ |/ / / / /     / /_/ / /_/ / /  (__  )  __/ /    
 __/ /\\__,_/ |__/|__/_/ /_/_____/ .___/\\__,_/_/  /____/\\___/_/     
/___/                    /_____/_/                                                              
                            v1.0.3
    """)
    # Set up CLI arguments
    arguments = argparse.ArgumentParser(prog='jawn_parser',
                                        usage='jawn_parser [-h] -c CLIENT_NAME FILE [FILE1 ...]')
    arguments._action_groups.pop()
    required = arguments.add_argument_group('required arguments')
    required.add_argument('-c', '--client', type=str, nargs=1, help='Client name', metavar='', default='[CLIENT]',
                          required=True)
    required.add_argument('files', type=str, nargs='+',
                          help='File to parse. Multiple files may be passed for combination into one spreadsheet.',
                          metavar='FILE')
    optional = arguments.add_argument_group('optional arguments')
    optional.add_argument('-i', '--include-info', action="store_true",
                          help='Select this flag to include informational or "none" ranked findings', default=False,
                          required=False)
    args = arguments.parse_args()
    file_info = analyze_files(args.files)
    # Parse that jawn
    if len(file_info) != -1:
        jawn_parser(args.client, args.include_info, file_info)
    else:
        print(str('[-] No valid scan files detected. Exiting...'))
        sys.exit()


if __name__ == '__main__':
    main()
