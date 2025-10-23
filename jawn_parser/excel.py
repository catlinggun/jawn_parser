import sys
import datetime
import xlsxwriter


def create_xlworkbook(client_name):
    try:
        print(str('[-] Creating .xlsx file...'))
        now = datetime.datetime.now()
        # Generate spreadsheet
        findings_log = xlsxwriter.Workbook(
            str('{}-Q{} {} Scan Results {}-{} {}.xlsx').format(
                now.strftime('%y'), now.month//3 + 1, client_name[0], now.month, now.day, now.strftime('%H%M%S')),
                {'strings_to_numbers': True})
        return findings_log
    except:
        print(sys.exc_info())


def create_xlsheet(table_name, findings_log, attributes, row_count):
    try:
        styles = {}
        # Set conditional formatting styles for risk factors
        crit_colors = {'Critical': '#0070C0',
                       'High': '#FF0000',
                       'Medium': '#FFC000',
                       'Low': '#00B050',
                       'None': '#808080'}
        for level in crit_colors:
            styles[level] = findings_log.add_format({'bold': True,
                                                'bg_color': crit_colors[level],
                                                'border_color': 'black',
                                                'font_color': 'white'})
            styles[level].set_align('center')
            styles[level].set_align('vcenter')
        current_sheet = findings_log.add_worksheet(table_name)
        risk_term = 'severity'
        if str.find(table_name, 'Nessus') != -1:
            if 'cvss3_base_score' in attributes:
                current_sheet.conditional_format(
                    1, attributes.index('cvss3_base_score'), row_count, attributes.index('cvss3_base_score'),
                                            {'type': 'data_bar',
                                             'min_type': 'num',
                                             'max_type': 'num',
                                             'min_value': 0,
                                             'max_value': 10,
                                             'bar_solid': '#5081BD'})
                current_sheet.set_tab_color('#007CC1')
                risk_term = 'risk_factor'
        # Format Qualys findings
        elif str.find(table_name, 'Qualys') != -1:
            if 'CVSS_BASE' in attributes:
                current_sheet.conditional_format(
                    1, attributes.index('CVSS_BASE'), row_count, attributes.index('CVSS_BASE'),
                                            {'type': 'data_bar',
                                             'min_type': 'num',
                                             'max_type': 'num',
                                             'min_value': 0,
                                             'max_value': 10,
                                             'bar_solid': '#638EC6'})
                current_sheet.set_tab_color('#EF342B')
        elif str.find(table_name, 'Burp') != -1:
            current_sheet.set_tab_color('#F79646')
        else:
            current_sheet.set_tab_color('#DAEEF3')
            return current_sheet
        for style in styles:
            current_sheet.conditional_format(1, attributes.index(risk_term), row_count, attributes.index(risk_term),
                                             {'type': 'cell',
                                              'criteria': 'equal to',
                                              'value': str('"' + style + '"'),
                                              'format': styles[style]})
        return current_sheet
    except:
        print(sys.exc_info())


def create_xltable(current_sheet, attributes, row_count):
    try:
        attrib_col_widths = {'addr': 30, 'MAC': 30, 'Manufacturer': 30, 'portid': 10, 'ostype': 15,
                             'product': 30, 'OS': 20, 'Version': 30, 'version': 30, 'extrainfo': 30, 'Vendor': 20,
                             'Status': 30, 'Dispute Language': 30, 'scan_target': 25, 'hostname': 40, 'host-fqdn': 30,
                             'host-ip': 20, 'state': 15, 'protocol': 10, 'port': 10, 'cvss_base_score': 15,
                             'risk_factor': 11, 'pluginName': 60, 'synopsis': 30, 'description': 30, 'solution': 30,
                             'plugin_output': 30, 'see_also': 15, 'xref': 15, 'cve': 12, 'operating-system': 30,
                             'svc_name': 30, 'os': 30, 'system-type': 30, 'severity': 11, 'bid': 30, 'cvss_vector': 30,
                             'cvss_temporal_score': 30, 'cvss_temporal_vector': 30, 'cvss3_base_score': 30,
                             'cvss3_vector': 30, 'cvss3_temporal_score': 30, 'cvss3_temporal_vector': 30,
                             'HOST_START': 30, 'HOST_END': 30, 'policy-used': 30, 'Credentialed_Scan': 30,
                             'pluginFamily': 30, 'pluginID': 30, 'plugin_type': 30, 'script_version': 30,
                             'host-uuid': 30, 'LastUnauthenticatedResults': 30, 'IP': 20, 'cvss_base': 15, 'title': 60,
                             'threat': 30, 'impact': 30, 'results': 30, 'CVSS_BASE': 15, 'TITLE': 60, 'TYPE': 15,
                             'DIAGNOSIS': 30, 'CONSEQUENCE': 30, 'SOLUTION': 30, 'RESULT': 30, 'host': 50, 'ip': 15,
                             'name': 40, 'path': 40, 'location': 40, 'confidence': 30, 'issueBackground': 30,
                             'remediationBackground': 30, 'references': 30, 'vulnerabilityClassifications': 30,
                             'issueDetail': 30, 'issueDetailItems': 30, 'request': 50, 'response': 50,
                             'responseRedirected': 50, 'filename': 25, 'cookies_set': 35, 'scriptinfo': 60}
        column = 0
        # Write the headers to the columns and adjust widths for each data point
        header_dict = []
        for header in attributes:
            header_dict.append( {'header': header} )
            current_sheet.set_column(column, column, attrib_col_widths[header])
            column += 1
        table_style = None
        if str.find(current_sheet.name, 'Nmap') != -1:
            table_style = 'Table Style Medium 13'
        if str.find(current_sheet.name, 'Nessus') != -1:
            table_style = 'Table Style Medium 9'
        if str.find(current_sheet.name, 'Qualys') != -1:
            table_style = 'Table Style Medium 10'
        if str.find(current_sheet.name, 'Burp') != -1:
            table_style = 'Table Style Medium 14'
        current_sheet.add_table(
            0, 0, row_count - 1, len(attributes) - 1, {'style': table_style, 'columns': header_dict})
    except:
        print(sys.exc_info())

