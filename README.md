# directoryCheatsheet

# 📂 Sysadmin & SOC Analyst Cheatsheet: Must-Know Directories (Windows & Linux)

## 🪟 Windows Directories

### Credential & Access Logs

* `C:\Windows\System32\config\SAM`
  Stores local password hashes (a prime target for credential dumping attacks).

* `C:\Windows\repair\SAM`
  Backup of user credentials — may be targeted if the main SAM is protected.

* `C:\Windows\System32\config\SECURITY`
  Contains security policies and access control configurations.

### System & Event Logs

* `C:\Windows\System32\winevt\`
  Stores `.evtx` Windows Event Log files — crucial for SIEM and forensic analysis.

* `C:\Windows\System32\config\SYSTEM`
  Registry hive tracking system-wide configuration changes.

* `C:\Windows\System32\config\SOFTWARE`
  Registry hive with info on installed software and associated changes.

### Malware & Threat Hunting Indicators

* `C:\Windows\Prefetch\`
  Tracks recently executed programs; useful for building forensic timelines.

* `C:\Windows\AppCompat\Programs\Amcache.hve`
  Logs program execution history — excellent for lateral movement detection.

* `C:\Users\*\NTUSER.dat`
  User-specific registry settings (often leveraged for persistence or hiding malware).

### Persistence & Startup Investigations

* `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
  User-specific startup folder — commonly used by malware.

* `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
  Startup folder for **all users** — can be abused for persistence across accounts.

### Other Important Windows Directories

* `C:\Windows\System32`
  Core system files and executables. Includes tools like `cmd.exe`, `reg.exe`.

* `C:\Windows\SysWOW64`
  32-bit binaries on 64-bit systems. Often targeted for DLL injection.

* `C:\Users\<username>`
  User profiles with personal data, configs, and documents.

* `C:\Users\<username>\AppData\Local`
  Local (non-roaming) app data. Target for malware persistence.

* `C:\Users\<username>\AppData\Roaming`
  Roaming profile data synced in domain environments.

* `C:\Program Files`
  64-bit applications default install location.

* `C:\Program Files (x86)`
  32-bit applications default install location.

* `C:\ProgramData`
  App data for all users, used by many installers.

* `C:\Windows\Temp`
  System temporary files. Often used by malware.

* `%TEMP%`
  User-specific temporary folder. Typically `C:\Users\<user>\AppData\Local\Temp`.

* `C:\Windows\Tasks` / `C:\Windows\System32\Tasks`
  Scheduled tasks used for automation or persistence.

* `C:\$Recycle.Bin`
  Recycle Bin contents, organized per user SID.

* `C:\Windows\Logs`
  Contains system logs, update logs, and diagnostics.

* `C:\Windows\Prefetch`
  Windows launch optimization data. Useful in timeline analysis.

---

## 🐧 Linux Directories

| Path               | Purpose                  | Notes                                           |
| ------------------ | ------------------------ | ----------------------------------------------- |
| `/etc`             | Configuration files      | System-wide settings (e.g., `passwd`, `shadow`) |
| `/var/log`         | Log files                | Crucial for monitoring and incident response    |
| `/home/<user>`     | User home directories    | User-specific files and configs                 |
| `/tmp`             | Temporary files          | Often writable by all users (watch for abuse)   |
| `/var/tmp`         | Persistent temp files    | Not cleared on reboot                           |
| `/bin`             | Essential user binaries  | Basic commands used in single-user mode         |
| `/sbin`            | System binaries          | Commands for system administration              |
| `/usr/bin`         | Additional user binaries | Most standard commands live here                |
| `/usr/sbin`        | System admin commands    | Additional tools for admins                     |
| `/lib`, `/usr/lib` | Libraries                | Used by binaries in `/bin` and `/usr/bin`       |
| `/boot`            | Boot loader files        | Includes `vmlinuz`, `initrd`, `grub` configs    |
| `/dev`             | Device files             | Represents hardware (disks, tty, etc.)          |
| `/proc`            | Kernel and process info  | Virtual filesystem, very useful for forensics   |
| `/sys`             | Kernel interface         | Used to change kernel parameters                |
| `/run`             | Runtime data             | PID files, sockets, mount points                |
| `/root`            | Home directory for root  | Should be monitored carefully                   |

---

## 🔍 Forensics & Monitoring Tips

* **Check Temp Folders**: Common malware drop locations

  * Windows: `%TEMP%`
  * Linux: `/tmp`

* **Look in Scheduled Tasks / Cron**:

  * Windows: `schtasks`, `Task Scheduler`
  * Linux: `/etc/crontab`, `/etc/cron.*`, `crontab -l`

* **Inspect Startup Locations**:

  * Windows: Registry (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`)
  * Linux: `~/.bashrc`, `~/.profile`, systemd services

* **Monitor Logs**:

  * Windows: `.evtx` files in `C:\Windows\System32\winevt\Logs`
  * Linux: `/var/log/auth.log`, `/var/log/syslog`, `/var/log/messages`

---

📌 *Keep this file updated as your toolkit grows or changes with your environment.*
