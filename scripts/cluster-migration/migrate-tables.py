import os

from tqdm import tqdm
from clickhouse_driver import Client as ClickhouseClient


WRITE_CLICKHOUSE_URL = os.environ["WRITE_CLICKHOUSE_URL"]


def stream_table(table_name, where_clause):
    with ClickhouseClient.from_url("clickhouse://backend-fsn.ooni.org/") as click:
        for row in click.execute_iter(f"SELECT * FROM {table_name} {where_clause}"):
            yield row


def copy_table(table_name, where_clause):
    with ClickhouseClient.from_url(WRITE_CLICKHOUSE_URL) as click_writer:
        buf = []
        for row in tqdm(stream_table(table_name=table_name, where_clause=where_clause)):
            buf.append(row)
            if len(buf) > 50_000:
                click_writer.execute(f"INSERT INTO {table_name} VALUES", buf)
                buf = []

        if len(buf) > 0:
            click_writer.execute(f"INSERT INTO {table_name} VALUES", buf)


if __name__ == "__main__":
    assert WRITE_CLICKHOUSE_URL, "WRITE_CLICKHOUSE_URL environment variable is not set"
    print("## copying `fastpath` table")
    copy_table("fastpath", "WHERE measurement_uid < '20241127'")
    print("## copying `jsonl` table")
    copy_table("jsonl", "WHERE measurement_uid < '20241127'")
    print("## copying `citizenlab` table")
    copy_table("citizenlab", "")
    print("## copying `citizenlab_flip` table")
    copy_table("citizenlab_flip", "")
