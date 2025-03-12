# OONI Devops

At a glance below is the overall architecture of OONI Infrastructure across our various locations:

```mermaid
flowchart TB
    apiorg([api.ooni.org])-->alb
    apiio([api.ooni.io])-->backend
    ecs[Backend API ECS]<-->ch[(Clickhouse Cluster)]
    subgraph Hetzner
        backend[OONI Backend Monolith]<-->ch
        monitoring[Monitoring host]
        pipeline[Pipeline v5]
    end
    subgraph AWS
    alb[API Load Balancer]<-->ecs
    alb-->backend
    ecs<-->s3[(OONI S3 Buckets)]
    s3<-->backend
    end
    subgraph Digital Ocean
        th[Web Connectivity Test helper]<-->alb
    end
```

For more details [Infrastructure docs](https://docs.ooni.org/devops/infrastructure/)
