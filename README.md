# Frabs Server Security Report

A read-only security check for any Linux server, from one command. The results appear as a
scored report, with what to fix first, at [security.frabs.net](https://security.frabs.net).

Open [security.frabs.net](https://security.frabs.net) to get your own code, then run the command it
shows you on the server:

```sh
curl -sL https://raw.githubusercontent.com/frabsnet/security-report/main/run.sh | sudo sh -s YOURCODE
```

No curl? `wget -qO- https://raw.githubusercontent.com/frabsnet/security-report/main/run.sh | sudo sh -s YOURCODE`

It runs without `sudo` too; checks that need root then show as "needs root".

## What it checks

| Area | Checks |
| --- | --- |
| Logins | Root login over SSH, password logins, SSH port and tries allowed, other accounts with root powers, accounts with no password |
| Open services | Databases and admin services (MySQL, Redis, MongoDB, Docker API, VNC and more) listening on every address, a firewall filtering incoming traffic, the Docker socket |
| Updates | Waiting security updates (apt, dnf, yum or apk), automatic updates, whether the newest kernel is running, uptime |
| Signs of compromise | Known crypto-miners, connections to mining-pool ports, scheduled jobs that download and run code, programs in temporary folders, root's SSH keys |
| Login attacks | Failed logins in the last 24 hours, the top 10 addresses behind them, and whether anything blocks repeat attackers |

## Read-only

It changes no setting, installs nothing and restarts nothing. Plain `sh`, so it runs on any Linux;
it uses tools already there (`curl` or `wget`, `awk`, `ss` or `netstat`, the package manager in
simulate or cache-only mode).

## What is sent

Only to `api.frabs.net`, for your report: each check's result, the OS, kernel and virtualisation
type, and the addresses that failed to log in to your server (so they can be checked against threat
lists). Never your server's hostname or addresses, passwords, keys, file contents or command lines.
Reports are kept for 7 days.

## License

Apache-2.0. Made by [Frabs](https://frabs.net).
