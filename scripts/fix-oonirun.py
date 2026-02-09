import os
import csv
import sys
import hashlib

ACCOUNT_ID_NEW = os.environ["HASH_PASS"]

def hash_email_address(email_address: str, key: str) -> str:
    em = email_address.encode()
    return hashlib.blake2b(em, key=key.encode("utf-8"), digest_size=16).hexdigest()


values_list = []
with open(sys.argv[1]) as in_file:
    csv_reader = csv.reader(in_file)
    next(csv_reader)
    for row in csv_reader:
        if row == []:
            continue
        count, account_id, author = row
        hashed_author = hash_email_address(author, "CHANGEME")
        hashed_author_new = hash_email_address(author, ACCOUNT_ID_NEW)
        # creator_account_id matches hash of old key, requires update
        if hashed_author == account_id:
            values_list.append(f"\n('{account_id}', '{hashed_author_new}')")
            print("WILL UPDATE")
        elif hashed_author_new == account_id:
            print("NEW-OK NO UPDATE NEEDED")
        else:
            print(f"BAD: {account_id} != {hashed_author} ({author}) - update not possible")

sql_query_final = f"""
UPDATE oonirun as t set
    creator_account_id = c.new_account_id
FROM (values
    {",".join(values_list)}
) as c(creator_account_id, new_account_id)
WHERE c.creator_account_id = t.creator_account_id
"""
print(sql_query_final)
