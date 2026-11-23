# credscheck-nxc

A Bash script for fast, scripted credential checks against lab/HTB targets,
built on top of [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) and
Nmap.

## What it does

1. Runs a quick Nmap TCP scan limited to the ports of the protocols you
   asked for, so nxc is never called against a closed port.
2. Splits open protocols into two execution phases and runs checks with either
   the credentials you supplied, or a blind-test set
   (`anonymous`/`guest`/empty):
   - **Phase 1 — Independent services (parallel per protocol):** `nfs`, `ftp`,
     `vnc`, `ssh` run concurrently (up to 4 workers, one per protocol) with
     per-protocol SQLite isolation and deterministic output collection.
   - **Phase 2 — Windows/AD protocols (sequential):** `smb`, `ldap`, `winrm`,
     `rdp`, `wmi`, `mssql` run sequentially with delays and early
     `STATUS_ACCOUNT_LOCKED_OUT` detection to avoid locking out AD accounts.
   - **SSH / WinRM / RDP / NFS / WMI** don't have a concept of an "anonymous"
     login, so in blind mode they only get a single availability probe instead
     of a full guessing list.
   - **MSSQL** additionally gets common SQL-auth defaults (`sa:sa`,
     `sa:<empty>`, `sa:Password123`, `sa:admin`) - SQL Server auth rarely has
     an account-lockout policy, unlike Active Directory.
3. Classifies every result (confirmed success / possible success / rejected
   / connection failed / timeout) and prints a colored summary table.
4. If anything looks promising, offers to launch the right interactive
   client for that protocol with the found credentials already filled in
   (smbclient, sshpass+ssh, lftp, xfreerdp, evil-winrm, Impacket
   mssqlclient/wmiexec, showmount, or `nxc ldap` for LDAP).

## Safety features

- **Hard attempt limit** (`--max-attempts`, default 15) - the script asks
  for confirmation before exceeding it, and then truly stops at the limit
  instead of just warning and continuing.
- **Random delay between attempts** (`--delay-min`/`--delay-max`) to avoid
  looking like a scripted flood.
- **Per-call timeout** (`--timeout`, default 45s) so one hanging connection
  (slow HTB VPN, firewalled port) can't freeze the whole run.
- **Passwords are shown in plain text by default** (you typed them, you
  know them) - pass `--mask` before sharing a log file with anyone else or
  uploading it anywhere outside your own disk.
- Deliberately skips guessing default creds on SMB/WinRM/RDP, since those
  usually sit behind Active Directory account-lockout policies.
- **Account lockout detection (`STATUS_ACCOUNT_LOCKED_OUT`)** - Windows/AD
  protocols run sequentially in Phase 2; if a lockout response is detected
  for a user, remaining Phase 2 attempts for that user are skipped immediately.

## Supported protocols

`smb` `ssh` `ftp` `winrm` `mssql` `rdp` `ldap` `wmi` `nfs` `vnc`

## Requirements

See [TOOLS.md](TOOLS.md). Short version: `nmap` and `nxc` are required,
everything else (smbclient, lftp, xfreerdp, etc.) is optional and only
needed for the interactive-launch feature.

## Installation

```bash
git clone https://github.com/Xzar-x/credcheck-nxc.git
cd credcheck-nxc
chmod +x credscheck.sh
```

## Usage

```bash
# Blind test (anonymous/guest/empty) on all supported protocols
./credscheck.sh -t 10.10.11.123

# Specific credentials
./credscheck.sh -t 10.10.11.123 -u admin -p 'P@ssw0rd!'

# Limit to a few protocols, tighter timeout, skip the interactive prompt
./credscheck.sh -t 10.10.11.123 --protocols smb,ssh,ftp --timeout 30 -n

# Save a log (masking passwords this time) and raise the attempt limit
./credscheck.sh -t 10.10.11.123 --protocols smb,ftp -m 30 --mask -o logs/scan1.log
```

Full option list: `./credscheck.sh -h`

## Logs

Never commit log files - see `.gitignore`. Default password masking is
*off*; logs saved without `--mask` contain plaintext credentials. Keep
anything you save under `logs/` (already ignored) and double-check before
sharing a log with anyone.

## Legal

For use only on infrastructure you are explicitly authorized to test -
your own labs, HackTheBox, or engagements with signed authorization.
Unauthorized use is illegal.

## License

MIT
