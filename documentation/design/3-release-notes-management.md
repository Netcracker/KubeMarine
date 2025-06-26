# 3. release notes management

Date: 2024-05-23

## Status

Proposal

## Context

1. There is Release Notes record published every release.
2. There is a patch list released with each kubemarine version and used every migration procedure. 
3. This patch list is not published somewhere. No information in specific Release Notes about patches coming with this release which should be taken into account during migration procedure
4. During migration procedure, specially frue several releases, need to understand the patches to be applied and manage this process if necessary

## Decision

Need to have a patch list within each Release Notes, including detailed information about patch

## Consequences

What becomes easier or more difficult to do and any risks introduced by the change that will need to be mitigated.

## Considered Options

1. Update gitlab CI.  Run in docker  `migrate_kubemarine --list` and `migrate_kubemarine --describe`
2. Update githab CI.  Run in `migrate_kubemarine --list` and `migrate_kubemarine --describe`
3. 
