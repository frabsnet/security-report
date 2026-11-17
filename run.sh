#!/bin/sh
# Frabs Server Security Report for Linux: https://security.frabs.net
#
# Checks this server's security and shows a scored report, with what to fix first, on
# security.frabs.net. Read-only: it changes no setting, installs nothing, and every file
# it makes goes in one temporary folder that is deleted when it finishes.
#
#   curl -sL https://raw.githubusercontent.com/frabsnet/security-report/main/run.sh | sudo sh -s YOURCODE
#
# Without sudo it still runs, but checks that need root (the firewall, password hashes,
# login logs, every process's connections) show as "needs root".
#
# What it sends to security.frabs.net: each check's result, the OS, kernel and package
# counts, and the addresses that failed to log in to this server (so they can be checked
# against threat lists). Never this server's hostname or addresses, user passwords,
# keys, file contents or command lines.

API="https://api.frabs.net/v1/tools/audit"
LC_ALL=C; export LC_ALL
PATH="$PATH:/usr/sbin:/sbin"

has() { command -v "$1" >/dev/null 2>&1; }
json() { printf '"%s"' "$(printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g' | cut -c1-290)"; }
post() {
  if [ "$HTTP" = curl ]; then curl -fsS -m 10 -X POST -H 'content-type: application/json' --data "$1" "$API/$CODE/event" </dev/null >/dev/null 2>&1
  else wget -q -T 10 -O /dev/null --header='content-type: application/json' --post-data="$1" "$API/$CODE/event" </dev/null >/dev/null 2>&1; fi
  return 0
}
step() { post "{\"step\":\"$1\",\"state\":\"$2\",\"detail\":$(json "$3")}"; [ "$2" = running ] && printf '  %-36s ' "$3"; [ "$2" = done ] && echo "done"; return 0; }
# One finding: id, area, status (pass, warn, fail, info, root), title, detail, how to fix.
FOUND=0
finding() {
  post "{\"finding\":{\"id\":$(json "$1"),\"area\":\"$2\",\"status\":\"$3\",\"title\":$(json "$4"),\"detail\":$(json "$5"),\"fix\":$(json "$6")}}"
  FOUND=$((FOUND + 1))
}
needs_root() { finding "$1" "$2" root "$3" "This check needs root. Run the command with sudo for it." ""; }

main() {
  CODE=$1
  case $CODE in
    [A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9]) ;;
    *) echo "Usage: curl -sL https://raw.githubusercontent.com/frabsnet/security-report/main/run.sh | sudo sh -s YOURCODE"
       echo "Get your code at https://security.frabs.net"; exit 1 ;;
  esac
  if has curl; then HTTP=curl; elif has wget; then HTTP=wget; else echo "This report needs curl or wget."; exit 1; fi
  if [ "$HTTP" = curl ]; then curl -fsS -m 15 -o /dev/null "$API/$CODE" </dev/null 2>/dev/null; else wget -q -T 15 -O /dev/null "$API/$CODE" </dev/null 2>/dev/null; fi
  if [ $? -ne 0 ]; then
    echo "This server can't reach https://api.frabs.net, so the report couldn't be shown."
    echo "Check the code is right and was made in the last two hours: https://security.frabs.net"; exit 1
  fi
  ROOT=no; [ "$(id -u)" = 0 ] && ROOT=yes
  WORK=$(mktemp -d 2>/dev/null || { d="/tmp/frabs-security.$$"; mkdir "$d" && echo "$d"; })
  trap 'rm -rf "$WORK"' EXIT
  trap 'echo; echo "Stopped. Nothing was changed, and its temporary files are gone."; rm -rf "$WORK"; exit 130' INT TERM

  echo
  echo "  Frabs Server Security Report · https://security.frabs.net/$CODE"
  echo "  Read-only: nothing is changed or installed."
  [ $ROOT = no ] && echo "  Not running as root: some checks will be skipped. Add sudo for the full report."
  echo
  post "{\"state\":\"start\",\"platform\":\"linux\",\"root\":$([ $ROOT = yes ] && echo true || echo false)}"

  # ---- the system
  step system running "Reading the system"
  os=Linux; [ -r /etc/os-release ] && os=$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-${NAME:-Linux}}")
  virt=$(systemd-detect-virt 2>/dev/null); [ -z "$virt" ] && virt=unknown
  up=$(cut -d. -f1 /proc/uptime 2>/dev/null); updays=$(( ${up:-0} / 86400 ))
  post "{\"system\":{\"os\":$(json "$os"),\"kernel\":$(json "$(uname -r)"),\"arch\":$(json "$(uname -m)"),\"virtualisation\":$(json "$virt"),\"uptime_days\":$updays,\"root\":$([ $ROOT = yes ] && echo true || echo false)}}"
  step system done "Reading the system"

  # ---- logins: SSH and accounts
  step logins running "SSH and accounts"
  if has sshd || [ -f /etc/ssh/sshd_config ]; then
    cfg=
    if [ $ROOT = yes ] && has sshd; then cfg=$(sshd -T 2>/dev/null); fi
    if [ -z "$cfg" ]; then cfg=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | sed 's/#.*//' | tr 'A-Z' 'a-z'); fi
    val() { printf '%s\n' "$cfg" | awk -v k="$1" 'tolower($1) == k { print tolower($2); exit }'; }
    prl=$(val permitrootlogin); pa=$(val passwordauthentication); port=$(val port); mat=$(val maxauthtries)
    [ -z "$prl" ] && prl="prohibit-password"; [ -z "$pa" ] && pa=yes; [ -z "$port" ] && port=22
    case $prl in
      yes) finding ssh_root logins fail "Root can log in over SSH with a password" "PermitRootLogin is yes." "Set PermitRootLogin to prohibit-password (keys only) or no in /etc/ssh/sshd_config, then reload sshd." ;;
      no) finding ssh_root logins pass "Root can't log in over SSH" "PermitRootLogin is no." "" ;;
      *) finding ssh_root logins pass "Root logs in over SSH with keys only" "PermitRootLogin is $prl." "" ;;
    esac
    if [ "$pa" = yes ]; then finding ssh_password logins warn "SSH accepts passwords" "PasswordAuthentication is on, so bots can keep guessing passwords." "Use SSH keys and set PasswordAuthentication no, after checking your key works."
    else finding ssh_password logins pass "SSH accepts keys only" "PasswordAuthentication is off." ""; fi
    if [ "$port" = 22 ]; then finding ssh_port logins info "SSH is on the standard port 22" "Bots scan port 22 all day. Moving it cuts the noise, but keys matter far more." ""
    else finding ssh_port logins pass "SSH is on port $port" "Not the default port, so far fewer bots find it." ""; fi
    if [ -n "$mat" ] && [ "$mat" -gt 6 ] 2>/dev/null; then finding ssh_tries logins warn "SSH allows $mat password tries per connection" "Each connection can guess $mat times." "Set MaxAuthTries 3 in /etc/ssh/sshd_config."; fi
  else
    finding ssh_none logins info "No SSH server found" "Nothing to check for SSH." ""
  fi
  others=$(awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd 2>/dev/null | tr '\n' ' ')
  if [ -n "$others" ]; then finding uid0 logins fail "Other accounts have root powers" "Accounts with user ID 0 besides root: $others" "Remove these accounts or give them their own user ID, unless you set them up on purpose."
  else finding uid0 logins pass "Only root has root powers" "No other account has user ID 0." ""; fi
  if [ -r /etc/shadow ]; then
    empty=$(awk -F: '($2 == "") { print $1 }' /etc/shadow | tr '\n' ' ')
    if [ -n "$empty" ]; then finding empty_pw logins fail "Accounts with no password" "Can log in with an empty password: $empty" "Set a password or lock them: passwd -l <name>."
    else finding empty_pw logins pass "Every account has a password or is locked" "No empty passwords." ""; fi
  else needs_root empty_pw logins "Accounts with no password"; fi
  shells=$(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ { n++ } END { print n + 0 }' /etc/passwd 2>/dev/null)
  finding shells logins info "$shells accounts can log in" "Accounts with a login shell." "Lock any you don't use."
  step logins done "SSH and accounts"

  # ---- exposure: what listens on the internet, and the firewall
  step exposure running "Open services and firewall"
  if has ss; then lst=$(ss -H -tuln 2>/dev/null | awk '{ print $1, $5 }'); elif has netstat; then lst=$(netstat -tuln 2>/dev/null | awk 'NR > 2 { print $1, $4 }'); else lst=; fi
  if [ -z "$lst" ]; then finding listen exposure info "Couldn't list listening services" "Neither ss nor netstat is installed." ""
  else
    public=$(printf '%s\n' "$lst" | awk '{ n = split($2, a, ":"); port = a[n]; addr = substr($2, 1, length($2) - length(port) - 1); if (addr ~ /^(0\.0\.0\.0|\*|\[::\]|::|\[::ffff:0\.0\.0\.0\])$/) print tolower($1), port }' | sort -u)
    count=$(printf '%s\n' "$public" | grep -c . )
    risky=
    for pair in "3306 MySQL" "5432 PostgreSQL" "6379 Redis" "27017 MongoDB" "11211 Memcached" "9200 Elasticsearch" "2375 Docker API" "2379 etcd" "5900 VNC" "23 Telnet" "21 FTP" "445 SMB" "139 NetBIOS" "111 rpcbind" "161 SNMP" "5984 CouchDB" "8086 InfluxDB" "9000 PHP-FPM"; do
      p=${pair%% *}; n=${pair#* }
      printf '%s\n' "$public" | grep -q " $p\$" && risky="$risky$n ($p), "
    done
    if [ -n "$risky" ]; then finding risky_ports exposure fail "Services open to the whole internet that usually shouldn't be" "${risky%, }" "Bind them to 127.0.0.1 or a private network, or allow only your own addresses in the firewall."
    else finding risky_ports exposure pass "No databases or admin services open to the internet" "None of the usual risky ports listen on every address." ""; fi
    ports=$(printf '%s\n' "$public" | awk '{ print $2 "/" $1 }' | sort -n | uniq | tr '\n' ' ')
    if [ "$count" = 1 ]; then what="1 port listens"; else what="$count ports listen"; fi
    finding public_ports exposure info "$what on every address" "$ports" "Anything here is reachable from the internet unless a firewall blocks it."
  fi
  if [ $ROOT = yes ]; then
    fw=
    has nft && [ "$(nft list ruleset 2>/dev/null | grep -c 'hook input')" -gt 0 ] && fw="nftables"
    [ -z "$fw" ] && has iptables && [ "$(iptables -S INPUT 2>/dev/null | grep -cv '^-P INPUT ACCEPT')" -gt 0 ] && fw="iptables"
    has ufw && ufw status 2>/dev/null | grep -q "Status: active" && fw="ufw"
    has firewall-cmd && firewall-cmd --state >/dev/null 2>&1 && fw="firewalld"
    if [ -n "$fw" ]; then finding firewall exposure pass "A firewall is on" "Filtering incoming traffic with $fw." ""
    else finding firewall exposure warn "No firewall filtering incoming traffic" "Every listening service is reachable from the internet." "Turn on ufw (Ubuntu/Debian) or firewalld (RHEL), allowing only the ports you need."; fi
  else needs_root firewall exposure "Firewall"; fi
  if [ -S /var/run/docker.sock ]; then
    perm=$(stat -c %a /var/run/docker.sock 2>/dev/null)
    case $perm in *[2367]) finding docker_sock exposure fail "Anyone on this server can control Docker" "The Docker socket is writable by every user (mode $perm), which is the same as root." "chmod 660 /var/run/docker.sock" ;;
      *) finding docker_sock exposure pass "The Docker socket is locked down" "Mode $perm." "" ;; esac
  fi
  step exposure done "Open services and firewall"

  # ---- patching
  step patching running "Updates and kernel"
  if has apt-get; then
    sim=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst ')
    total=$(printf '%s\n' "$sim" | grep -c '^Inst'); sec=$(printf '%s\n' "$sim" | grep -ci 'securi')
    if [ "$sec" -gt 0 ]; then finding updates patching fail "$sec security updates waiting" "$total updates in all, $sec of them security fixes (from the package lists as they are now)." "apt update && apt upgrade"
    elif [ "$total" -gt 0 ]; then finding updates patching warn "$total updates waiting" "No security fixes among them." "apt update && apt upgrade"
    else finding updates patching pass "Up to date" "No waiting updates in the package lists as they are now." ""; fi
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then finding auto_updates patching pass "Security updates install automatically" "unattended-upgrades is on." ""
    else finding auto_updates patching warn "Security updates don't install automatically" "unattended-upgrades isn't turned on." "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"; fi
  elif has dnf || has yum; then
    pm=dnf; has dnf || pm=yum
    sec=$($pm -q --cacheonly updateinfo list --security 2>/dev/null | grep -c .)
    total=$($pm -q --cacheonly check-update 2>/dev/null | grep -c '^[a-zA-Z0-9]')
    if [ "${sec:-0}" -gt 0 ]; then finding updates patching fail "$sec security updates waiting" "$total updates in all." "$pm upgrade --security"
    elif [ "${total:-0}" -gt 0 ]; then finding updates patching warn "$total updates waiting" "No security fixes among them." "$pm upgrade"
    else finding updates patching pass "Up to date" "No waiting updates in the cached package lists." ""; fi
    if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || systemctl is-enabled dnf-automatic-install.timer >/dev/null 2>&1; then finding auto_updates patching pass "Updates install automatically" "dnf-automatic is on." ""
    else finding auto_updates patching warn "Updates don't install automatically" "dnf-automatic isn't turned on." "$pm install dnf-automatic && systemctl enable --now dnf-automatic-install.timer"; fi
  elif has apk; then
    total=$(apk version -l '<' 2>/dev/null | grep -c '<')
    if [ "$total" -gt 0 ]; then finding updates patching warn "$total updates waiting" "Alpine packages with newer versions." "apk update && apk upgrade"
    else finding updates patching pass "Up to date" "No newer packages in the index as it is now." ""; fi
  else finding updates patching info "Couldn't check updates" "No apt, dnf, yum or apk here." ""; fi
  if [ -f /var/run/reboot-required ]; then finding reboot patching warn "A reboot is needed to finish updates" "The new kernel or libraries aren't running yet." "Reboot when it suits you."
  else
    run=$(uname -r); newest=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's#/boot/vmlinuz-##' | sort -V | tail -1)
    if [ -n "$newest" ] && [ "$newest" != "$run" ]; then finding reboot patching warn "A newer kernel is installed but not running" "Running $run, installed $newest." "Reboot when it suits you."
    else finding reboot patching pass "Running the newest installed kernel" "$run" ""; fi
  fi
  if [ "$updays" -gt 180 ]; then finding uptime patching warn "Up for $updays days" "Kernel fixes need a reboot (or live patching) to apply." "Plan a reboot, or turn on live patching."; fi
  step patching done "Updates and kernel"

  # ---- signs of compromise
  step compromise running "Signs of compromise"
  miners=$(ps -eo comm= 2>/dev/null | grep -Ei '^(xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing|kthreaddi|sysupdate|networkservice|dbused|xmrigminer|ccminer|t-rex|lolminer|nbminer|phoenixminer)$' | sort -u | tr '\n' ' ')
  if [ -n "$miners" ]; then finding miner compromise fail "Crypto-mining programs are running" "Running: $miners" "These are almost always installed by an attacker. Kill them, find how they got in (cron, SSH keys, a web app) and rebuild if in doubt."
  else finding miner compromise pass "No known mining programs running" "Checked the process list for well-known miners." ""; fi
  if has ss; then
    pool=$(ss -H -tn state established 2>/dev/null | awk '{ n = split($4, a, ":"); print a[n] }' | grep -E '^(3333|4444|5555|7777|8888|9999|14433|14444|45700)$' | sort | uniq -c | awk '{ printf "%s x%s, ", $2, $1 }')
    if [ -n "$pool" ]; then finding pool_ports compromise warn "Connections to ports mining pools use" "${pool%, }" "Check which program holds them: ss -tnp | grep -E ':(3333|4444|5555|7777|14444)'."
    else finding pool_ports compromise pass "No connections to mining-pool ports" "" ""; fi
  fi
  bad=
  for f in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
    [ -r "$f" ] || continue
    grep -Eqi '(curl|wget)[^#|]*\|[[:space:]]*(ba)?sh|base64[[:space:]]+-d|/dev/shm/|/tmp/\.[a-z]' "$f" 2>/dev/null && bad="$bad$(basename "$f") "
  done
  if [ -n "$bad" ]; then finding cron compromise fail "Scheduled jobs that download and run code" "Suspicious lines in: $bad" "Read these cron files. Lines that pipe a download into a shell are a classic sign of a break-in."
  else finding cron compromise pass "No suspicious scheduled jobs" "Checked the cron files this account can read." ""; fi
  [ $ROOT = no ] && needs_root cron_all compromise "Every user's scheduled jobs"
  hidden=$(find /tmp /var/tmp /dev/shm -maxdepth 2 -type f -perm -u+x 2>/dev/null | head -20 | wc -l)
  if [ "$hidden" -gt 0 ]; then finding tmp_exec compromise warn "$hidden programs in temporary folders" "Executable files in /tmp, /var/tmp or /dev/shm, where attackers often drop tools." "ls -la /tmp /var/tmp /dev/shm and remove anything you don't recognise."
  else finding tmp_exec compromise pass "No programs in temporary folders" "" ""; fi
  if [ $ROOT = yes ]; then
    # Keys only: no blank lines or comments. grep -c prints 0 itself when nothing matches, so no "|| echo 0" (that made "00").
    keys=$(grep -c -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' /root/.ssh/authorized_keys 2>/dev/null); keys=${keys:-0}
    case $keys in
      0) finding root_keys compromise pass "No SSH keys can log in as root" "" "" ;;
      1) finding root_keys compromise info "1 SSH key can log in as root" "Keys in /root/.ssh/authorized_keys." "Remove it if you don't recognise it." ;;
      *) finding root_keys compromise info "$keys SSH keys can log in as root" "Keys in /root/.ssh/authorized_keys." "Remove any key you don't recognise." ;;
    esac
  else needs_root root_keys compromise "SSH keys that can log in as root"; fi
  step compromise done "Signs of compromise"

  # ---- attacks: failed logins in the last 24 hours
  step attacks running "Login attacks, last 24 hours"
  logs=
  if has journalctl && [ $ROOT = yes ]; then logs=$(journalctl -q --since "24 hours ago" -u ssh -u sshd --no-pager 2>/dev/null)
  fi
  if [ -z "$logs" ]; then for f in /var/log/auth.log /var/log/secure; do [ -r "$f" ] && logs=$(tail -n 200000 "$f"); done; fi
  if [ -z "$logs" ]; then
    if [ $ROOT = no ]; then needs_root attacks attacks "Login attacks"; else finding attacks attacks info "No SSH login log found" "Neither the journal nor auth.log/secure had SSH entries." ""; fi
  else
    fails=$(printf '%s\n' "$logs" | grep -E 'Failed password|Invalid user|authentication failure|Connection closed by authenticating user|maximum authentication attempts')
    n=$(printf '%s\n' "$fails" | grep -c .)
    top=$(printf '%s\n' "$fails" | grep -oE 'from [0-9a-fA-F:.]+|rhost=[0-9a-fA-F:.]+' | sed 's/from //; s/rhost=//' | sort | uniq -c | sort -rn | head -10)
    list=$(printf '%s\n' "$top" | awk 'NF == 2 { printf "{\"ip\":\"%s\",\"count\":%d},", $2, $1 }')
    ips=$(printf '%s\n' "$top" | grep -c .)
    post "{\"attacks\":{\"failed\":$n,\"sources\":$ips,\"top\":[${list%,}]}}"
    if [ "$n" -gt 1000 ]; then finding attacks attacks fail "$n failed logins in 24 hours" "Bots are guessing passwords on this server all day." "Use SSH keys only, and block repeat offenders (fail2ban, CrowdSec or Frabs)."
    elif [ "$n" -gt 50 ]; then finding attacks attacks warn "$n failed logins in 24 hours" "Normal background noise for an internet server, but each one is a guess at a password." "Use SSH keys only and block repeat offenders."
    else finding attacks attacks pass "$n failed logins in 24 hours" "Very little password guessing." ""; fi
    if has fail2ban-client || has cscli; then finding blocker attacks pass "Repeat attackers are blocked" "fail2ban or CrowdSec is installed." ""
    elif has sshd || [ "$n" -gt 50 ]; then finding blocker attacks warn "Nothing blocks repeat attackers" "No fail2ban or CrowdSec, so a bot can keep guessing." "Install fail2ban, CrowdSec, or let Frabs block them at the network."; fi
  fi
  step attacks done "Login attacks, last 24 hours"

  step cleanup running "Removing its temporary files"
  rm -rf "$WORK"
  step cleanup done "Removing its temporary files"
  post '{"state":"finished"}'
  echo
  echo "  Done: $FOUND checks. Your report: https://security.frabs.net/$CODE"
  echo
}

main "$@"
