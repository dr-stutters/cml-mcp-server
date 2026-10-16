# Recipe verification in CI: self-hosted runner setup

The workflow `.github/workflows/recipes-verify.yml` runs `scripts/recipes.py ci`: for each recipe it
verifies the lab against its contract (`cml_verify_recipe`) and writes a pass/fail table to the job
summary. It leaves the controller as it found it:

| Lab state before | What the run does |
|---|---|
| STARTED | verifies it as it is (someone may be using it; nothing is started or stopped) |
| STOPPED / defined | starts it, waits for the boot, verifies, **stops it again** |
| missing | skipped, unless the run was started with `build_missing` (then built, verified, stopped, kept) |
| needs licences held by other labs | skipped (it never stops another lab) |

A lab in any other state (QUEUED, BOOTED, ...) is skipped: someone is starting or changing it. A
failing check is retried once after 3 minutes (slow cat9000v data planes). The job exits non-zero
when a verified recipe fails, errors, or a lab it started could not be stopped; **skipped recipes
count as success**, so read the table. If the job is cancelled, the script stops the lab it was
working on before exiting (SIGTERM); a forced kill can leave that lab running.

GitHub-hosted runners can't reach the lab, so the job needs a **self-hosted runner** on a host
that reaches CML (198.18.128.10) and the lab appliances, e.g. cortex. Nothing has been
installed yet: the workflow only runs when the repository variable `RECIPE_CI_ENABLED` is `true`
and a runner with the labels `self-hosted` and `cml-lab` is online. It triggers on manual
dispatch only (the nightly schedule is commented out in the workflow).

## Security model (read first)

- **Keep the repository private.** A self-hosted runner on a public repository can be made to run
  code from anyone's pull request. The workflow has no `pull_request` trigger: only
  `workflow_dispatch` (and, once enabled, `schedule`), so only people with write access can start it.
- **Main only.** `workflow_dispatch` can target any branch, and a branch can carry an edited workflow
  or script. The job therefore runs only when `github.ref` is `refs/heads/main`, and the `cml-lab`
  environment (which holds the secrets) **must** be restricted to the `main` branch (step "Configure"
  below), so a workflow edited on another branch never gets the secrets.
- **Dedicated, unprivileged user.** Run the runner as its own account (`gh-runner` below), not as
  `reptar`, with no sudo, not in the `docker` group, and no SSH keys or other credentials in its
  home. Whatever a workflow step runs, runs with this user's rights on cortex.
- **Repository-scoped runner** (Settings > Actions > Runners of `dr-stutters/cml-mcp-server`), not
  an organisation runner, so other repositories can't schedule jobs on it.
- **Secrets in a GitHub Environment** named `cml-lab` (Settings > Environments) with *Deployment
  branches* = `main` (mandatory). *Required reviewers* (approve every run before it gets the CML
  password) are recommended; on a private repository they need a paid GitHub plan.
- Third-party actions are pinned to commit SHAs (they run on a host that holds secrets).
- Consider registering the runner with `--ephemeral` (one job per registration, clean `_work`);
  it then needs re-registering after every run, so it suits an automated re-register script.
- **Least-privilege tokens:**
  - No token for core: it is bundled into the wheel the job builds (L35, core ADR-005).
  - CML account: today the admin account (licence planning reads `/system` and every lab's nodes).
    Once roadmap L17 (non-admin support) lands, use a dedicated CML user instead.
- `actions/checkout` runs with `persist-credentials: false`, so the job's `GITHUB_TOKEN` is not
  left in the working copy. The workflow's token has `contents: read` only.
- The job uses a fixed concurrency group, so two runs never start and stop labs at the same time.
- Runner software auto-updates by default; keep that on.

## Install (on cortex, as a user with sudo; about 10 minutes)

1. Create the runner account:
   ```bash
   sudo useradd --create-home --shell /bin/bash gh-runner
   sudo passwd --lock gh-runner           # no password logins
   ```
2. In GitHub: `dr-stutters/cml-mcp-server` > Settings > Actions > Runners > **New self-hosted
   runner** > Linux x64. Keep that page open: it shows the current runner version, the download
   URL, its SHA-256 and a one-hour registration token.
3. Download and check the runner as `gh-runner` (use the version and hash from that page):
   ```bash
   sudo -iu gh-runner
   mkdir actions-runner && cd actions-runner
   curl -o runner.tar.gz -L https://github.com/actions/runner/releases/download/v<VERSION>/actions-runner-linux-x64-<VERSION>.tar.gz
   echo "<SHA256-from-the-page>  runner.tar.gz" | sha256sum -c
   tar xzf runner.tar.gz
   ```
4. Register it for this repository only, with the `cml-lab` label:
   ```bash
   read -rs RUNNER_TOKEN                   # paste the registration token (kept out of shell history)
   ./config.sh --url https://github.com/dr-stutters/cml-mcp-server --token "$RUNNER_TOKEN" \
     --name cortex-cml-lab --labels cml-lab --work _work --unattended
   exit                                    # back to your own user
   ```
5. Run it as a systemd service under `gh-runner`:
   ```bash
   # gh-runner's home is mode 0750 on Ubuntu 22.04+, so change into it as root
   sudo bash -c 'cd /home/gh-runner/actions-runner && ./svc.sh install gh-runner && ./svc.sh start && ./svc.sh status'
   ```
6. Check reachability as that user (cortex reaches the lab over the lab VPN):
   ```bash
   sudo -iu gh-runner curl -sk -o /dev/null -w '%{http_code}\n' https://198.18.128.10/api/v0/system_information
   ```
   Expect `200`. If the VPN is down the job fails at the first CML call.

## Configure the repository

1. Settings > Environments > **New environment** `cml-lab`:
   - secrets `CML_URL` (`https://198.18.128.10`), `CML_USERNAME`, `CML_PASSWORD` (from
     `~/MCP-Suite/cml-mcp-server/.env`);
   - *Deployment branches and tags* = **Selected branches: `main`** (required);
   - recommended: *Required reviewers* = you (paid plan for private repositories).
2. Settings > Secrets and variables > Actions > **Variables** > `RECIPE_CI_ENABLED` = `true`.
3. Actions > **recipes-verify** > Run workflow (optionally a recipe list such as `ftd-ha`). The job
   summary shows the table; the log shows each recipe's JSON result.
4. For nightly runs, uncomment the `schedule:` block in the workflow.

`uv` is installed by `astral-sh/setup-uv` into the runner's tool cache; nothing else is needed on
the host. The job also works from a laptop shell for comparison:
`uv run python scripts/recipes.py ci ftd-ha --summary /tmp/summary.md`.

## Disable or remove

- Pause: set `RECIPE_CI_ENABLED` to `false` (the job is skipped), or `sudo ./svc.sh stop`.
- Remove: `sudo ./svc.sh uninstall`, then as `gh-runner` run
  `./config.sh remove --token <REMOVAL-TOKEN>` (from the runner's page in GitHub), and finally
  `sudo userdel --remove gh-runner`.
