from datetime import datetime, timedelta
import csv

from tqdm import tqdm
from clickhouse_driver import Client as ClickhouseClient


START_TIME = datetime(2024, 11, 1, 0, 0, 0)
END_TIME = datetime(2024, 11, 10, 0, 0, 0)
SAMPLE_SIZE = 100


def sample_to_file(table_name):
    with ClickhouseClient.from_url("clickhouse://localhost/ooni") as click, open(
        f"{table_name}-sample.csv", "w"
    ) as out_file:
        writer = csv.writer(out_file)
        ts = START_TIME
        while ts < END_TIME:
            for row in click.execute_iter(
                f"""
                SELECT * FROM {table_name} 
                WHERE measurement_uid LIKE '{ts.strftime("%Y%m%d%H")}%'
                ORDER BY measurement_uid LIMIT {SAMPLE_SIZE}
                """
            ):
                writer.writerow(row)
            ts += timedelta(hours=1)


if __name__ == "__main__":
    sample_to_file("obs_web")
    sample_to_file("analysis_web_measurement")
