import sys
import sqlite3


def create_db(name):
    try:
        print(str('[-] Initializing Database...'))
        conn = sqlite3.connect(':memory:')
        database = conn.cursor()
        return database
    except:
        print(sys.exc_info())


def create_dbtable(name, attributes, database):
    col = int(1)
    # Build the SQL query dynamically
    execute_string = str('CREATE TABLE IF NOT EXISTS "{}" (').format(name)
    for key in attributes:
        # Casts the datatype for this one column so the excel conditional formatting works properly. yucky but w/e
        if key == 'cvss_base_score' or key == 'portid':
            execute_string += str('"{}" INTEGER').format(key)
        else:
            execute_string += str('"{}"').format(key)
        if col < len(attributes):
            execute_string += ', '
            col += 1
    execute_string += ')'
    database.execute(execute_string)
    return database


def insert_dbtable(name, finding, database):
    try:
        row = int(1)
        values = ()
        # Build the SQL query dynamically
        execute_string = str('INSERT INTO "{}" (').format(name)
        for key in finding:
            execute_string += str('"{}"').format(key)
            if row < len(finding):
                execute_string += ', '
                row += 1
        execute_string += ') VALUES ('
        row = int(1)
        for value in finding.values():
            values = values + (value,)
            execute_string += str('?')
            if row < len(finding):
                execute_string += ', '
                row += 1
        execute_string += ')'
        database.execute(execute_string, values)
    except:
        print(sys.exc_info())

