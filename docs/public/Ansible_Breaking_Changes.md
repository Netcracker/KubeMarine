
# 📜 Breaking Changes from Ansible 7.7.* to 11.4.*

*(Covering Ansible-Core 2.14 → 2.15 → 2.16)*

## ⚡ Breaking Changes

Here are some braking changes which can cause failures in your environment if you are using ansible playbooks -

| **Breaking Change** | **Expected Failure** | **Solution/Workaround** |
|:---------------------|:----------------------|:-------------------------|
| Python 3.8 is no longer supported (needs Python ≥ 3.9) | Ansible won't start. Error: Unsupported Python version detected. | Upgrade your Python to at least 3.9 or 3.10 across all environments. |
| Collections not bundled anymore (e.g., community.general, community.kubernetes) | Playbooks using those modules fail with module not found errors. | Add those collections manually in `requirements.yml` and install via `ansible-galaxy collection install -r requirements.yml`. |
| Module movement to collections (e.g., docker_* → community.docker) | Task failures like module not found: docker_container. | Update the module usage to use FQCN (Fully Qualified Collection Name), e.g., `community.docker.docker_container` instead of just `docker_container`. |
| Loop control stricter behavior | Unwanted output or failure during loops, unexpected labels. | Explicitly define `loop_control.label` or handle it via `item`. Adjust your loops manually if errors appear. |
| Jinja2 filter changes (select, reject, extract) stricter | Playbooks with Jinja filters error out like unexpected type 'NoneType' or unexpected value. | Audit your templates. Add defensive checks (`default()`) before using filters if possibility of None. Example: `mylist | default([])`. |
| URI module behavior tightened (ansible.builtin.uri) | Timeout behavior differs. Tasks that used to retry/timeout differently now behave more strictly (e.g., faster failure). | Tune `timeout` and `retries` parameters manually for critical network tasks. |
| Inventory plugin strict parsing | Inventory loading fails immediately if parsing errors (before was silent skip). | Fix your inventory formatting carefully. Run `ansible-inventory --list` to catch issues. |
| host_key_checking default stricter | SSH tasks might fail connecting to new hosts (host key checking strict by default). | Add `ANSIBLE_HOST_KEY_CHECKING=False` explicitly or manage `known_hosts` carefully. |
| Environment variables deprecated (ANSIBLE_SSH_ARGS, etc.) | Custom SSH args/behavior might be ignored, unexpected SSH failures. | Move SSH options to `ansible.cfg` or use explicit connection vars inside playbooks. |
| Role paths and Collection paths resolution changed | Roles/collections not found error if they relied on previous global paths. | Set `collections_paths` and `roles_path` explicitly inside `ansible.cfg`. |
| ansible.builtin.set_stats now needs explicit aggregation | Playbooks using set_stats may behave differently — missing custom variables. | Add aggregation keys properly in `set_stats`. |
| CLI Argument stricter parsing (e.g., -e) | Extra-vars parsing might fail if JSON/YAML not valid. | Ensure proper quotes and valid YAML/JSON formats in your `-e` arguments. |
| gather_subset=!all behavior change | setup module gathering facts may behave differently if you used gather_subset incorrectly. | Audit and fix your `gather_subset` usage. Use proper syntax. |

## 🚨 Important Special Cases

- **Callbacks/Plugins:**  
  If you wrote any custom plugins, many hooks have changed (especially `v2_runner_on_*` methods) — audit your plugins carefully.

- **Deprecation Warnings Turned into Errors:**  
  Code that gave warnings in 7.x might now throw **fatal errors**.



