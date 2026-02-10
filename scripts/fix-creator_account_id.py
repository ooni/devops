"""
This script is used to migrate account_id_hashes based on a dump from the database.

It verifies if the old hashes correspond to the OLD_KEY and forms a SQL UPDATE
query to be run on the database to update them to HASH_PASS.

To create a csv dump for this script, login to the postgresql instance using psql
and run:

\copy (SELECT COUNT(*) as count, creator_account_id,author FROM oonirun GROUP BY creator_account_id,author) TO 'dump-oonirun-prod.csv' csv header;

\copy (SELECT COUNT(*) as count, creator_account_id,email_address FROM oonifinding GROUP BY creator_account_id,email_address) TO 'dump-oonifinding-prod.csv' csv header;

Then copy to dump.csv over and run:

HASH_PASS_OLD=XXXX HASH_PASS=YYYY python fix-creator_account_id.py dump-oonirun-prod.csv oonirun

HASH_PASS_OLD=XXXX HASH_PASS=YYYY python fix-creator_account_id.py dump-oonifinding-prod.csv oonifinding

Then copy paste the SQL update script at the end into the DB to perform the update.
"""
import os
import csv
import sys
import hashlib

ACCOUNT_ID_NEW = os.environ["HASH_PASS"]
OLD_KEY = os.environ.get("HASH_PASS_OLD", "CHANGEME")

CSV_FN = sys.argv[1]
TABLE_NAME = sys.argv[2]

def hash_email_address(email_address: str, key: str) -> str:
    em = email_address.encode()
    return hashlib.blake2b(em, key=key.encode("utf-8"), digest_size=16).hexdigest()


values_list = []
with open(CSV_FN) as in_file:
    csv_reader = csv.reader(in_file)
    next(csv_reader)
    for row in csv_reader:
        if row == []:
            continue
        count, account_id, author = row
        hashed_author = hash_email_address(author, OLD_KEY)
        hashed_author_new = hash_email_address(author, ACCOUNT_ID_NEW)
        # creator_account_id matches hash of old key, requires update
        if hashed_author == account_id:
            values_list.append(f"\n('{account_id}', '{hashed_author_new}')")
            print("WILL UPDATE")
        elif hashed_author_new == account_id:
            print("NEW-OK NO UPDATE NEEDED")
        else:
            print(f"BAD: {account_id} != {hashed_author} ({author}) - will update with new")
            values_list.append(f"\n('{account_id}', '{hashed_author_new}')")

sql_query_final = f"""
UPDATE {TABLE_NAME} as t set
    creator_account_id = c.new_account_id
FROM (values
    {",".join(values_list)}
) as c(creator_account_id, new_account_id)
WHERE c.creator_account_id = t.creator_account_id
"""
print(sql_query_final)
