# Troubleshoot KubeMarine

APM package providing an AI-agent troubleshooting skill for KubeMarine — a CLI tool that installs, upgrades,
and maintains Kubernetes clusters on bare metal and VM nodes.

## Skills

| Skill                     | Description                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------ |
| `troubleshoot-kubemarine` | Diagnose and resolve KubeMarine procedure failures and Kubernetes operational issues |

## Structure

```
agent-packages/troubleshoot-kubemarine/
├── apm.yml
├── README.md
└── .apm/
    ├── instructions/
    │   └── troubleshoot-kubemarine.instructions.md
    └── skills/
        └── troubleshoot-kubemarine/
            ├── SKILL.md
            └── references/
                └── Troubleshooting.md   # mirrors docs/public/Troubleshooting.md (GitHub)
```

`references/Troubleshooting.md` is a copy of `docs/public/Troubleshooting.md` from this repository, kept for the
agent to consult for full alert strings, stack traces, and step-by-step fixes. `SKILL.md` intentionally does not
duplicate that detail — keep both files in sync when the source troubleshooting guide changes.

> Automated doc sync and `apm.yml` registration (root `devDependency`, CI jobs) are not set up yet — this package
> currently only contains the skill itself.

## Installing directly

```bash
apm install Netcracker/KubeMarine/agent-packages/troubleshoot-kubemarine
```
