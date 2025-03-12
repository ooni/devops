"""
Dump OONI findings for clickhouse into postgres by performing appropriate
transformations.

To setup run:

pip install psycopg2 clickhouse-driver

Then:

OONI_PG_PASSWORD=XXXX python migrate-oonifindings.py
"""
import os
import json

from clickhouse_driver import Client as Clickhouse
import psycopg2


def dump_oonifindings_clickhouse():
    client = Clickhouse("localhost")

    rows, cols = client.execute("SELECT * FROM incidents", with_column_types=True)
    col_names = list(map(lambda x: x[0], cols))

    findings = []
    for row in rows:
        d = dict(zip(col_names, row))
        
        row = {
            "finding_id": d["id"],
            "update_time": d["update_time"],
            "start_time": d["start_time"],
            "end_time": d["end_time"],
            "create_time": d["create_time"],
            "creator_account_id": d["creator_account_id"],
            "reported_by": d["reported_by"],
            "title": d["title"],
            "short_description": d["short_description"],
            "text": d["text"],
            "event_type": d["event_type"],
            "published": d["published"],
            "deleted": d["deleted"],
            "email_address": d["email_address"],
            "country_codes": json.dumps(d["CCs"]),
            "tags": json.dumps(d["tags"]),
            "asns": json.dumps(d["ASNs"]),
            "domains": json.dumps(d["domains"]),
            "links": json.dumps(d["links"]),
            "test_names": json.dumps(d["test_names"]),
        }
        findings.append(row)

    return findings


def insert_findings_postgresql(data_to_insert):
    db_params = {
        'dbname': 'oonipg',
        'user': 'oonipg',
        'password': os.environ["OONI_PG_PASSWORD"],
        'host': 'ooni-tier0-postgres'
    }

    conn = psycopg2.connect(**db_params)
    cur = conn.cursor()

    col_names = list(data_to_insert[0].keys())
    col_values = ["%s"]*len(col_names)
    insert_query = f'INSERT INTO oonifinding ({",".join(col_names)}) VALUES ({",".join(col_values)})'

    insert_count = 0
    try:
        for row in data_to_insert:
            values = [row[cn] for cn in col_names]
            cur.execute(insert_query, values)
            insert_count += 1
        conn.commit()
        print("Data inserted successfully")
    except Exception as e:
        conn.rollback()
        print(f"Failed after {insert_count} rows at row:")
        print(row)
        print(f"An error occurred: {e}")
        raise e
    finally:
        # Close the cursor and connection
        cur.close()
        conn.close()


valid_links = dump_oonifindings_clickhouse()
insert_findings_postgresql(valid_links)
