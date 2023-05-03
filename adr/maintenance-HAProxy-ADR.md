# Title
ADR for HAProxy Maintenance Mode switiching
## Status

Proposed

## Context

Currently there is automated procedure to enable/disable the maintenance mode for HAProxy load balancer.
We are developing a new procedure which will help us to enable/disable maintenance mode by a single command as below

```
kubemarine haproxy_mntc enable/disable
```

## Decision

Adding a new procedure to Kubemarine distribution for managing the maintenance mode for HAProxy load balancers.

## Consequences

Enabling or disbaling the maintenance mode will be an easy step after implementing this procedure.
It will be just one command task.
