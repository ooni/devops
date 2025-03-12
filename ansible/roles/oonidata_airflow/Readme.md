## Airflow role deployment notes

There are a few pieces that are dependencies to this role running properly that
you will have to do manually:

* Setup the postgresql database and create the relevant DB and account.

Be sure to give correct permissions to the airflow user. Here is a relevant snippet:
```
CREATE DATABASE airflow
CREATE ROLE airflow WITH PASSWORD '' LOGIN;
GRANT ALL PRIVILEGES ON DATABASE airflow TO airflow;
GRANT ALL ON SCHEMA public TO airflow;
```

* For some reason the admin account creation is failing. This is likely a bug
  in the upstream role. During the last deploy this was addressed by logging
into the host and running the create task manually:
```
AIRFLOW_CONFIG=/etc/airflow/airflow.cfg AIRFLOW_HOME=/opt/airflow/ /opt/airflow/bin/airflow users create --username admin --password XXX --firstname Open --lastname Observatory --role Admin --email admin@ooni.org
```

* Once the setup is complete, you will then have to login to the host using the
  admin user and go into Admin->Configuration and add the `clickhouse_url`
variable
