# dsh-plugin-folder-trust

Windows-only DeepSeek Harness plugin. When a workspace folder is added, it asks once whether to
trust it, then grants the NTFS rights DSH's workspace-write sandbox needs -- including pushing the
capability grant and the Low integrity label through folders that already exist. Starting, quitting
and repairing show live progress; the composer and Settings list every workspace's permission state.

When the folder's owner belongs to another machine (a copied folder), the account cannot rewrite its
permissions at all; the repair says so and asks Windows for one UAC elevation, which the user must
approve. Declining leaves the folder untouched.

See [README.zh.md](README.zh.md) for the full design notes (Chinese).

## Install

    dsh plugin install dsh-plugin-folder-trust

## Requirements

Windows 10/11. The permission helpers run under PowerShell 7 when it is installed and fall back to
Windows PowerShell 5.1 otherwise; `FOLDER_TRUST_POWERSHELL` pins one explicitly. No plugin is
required: 5.1 ships with Windows, and it is spawned with a 5.1-only `PSModulePath` so a PowerShell 7
module path inherited from the host cannot break `Get-Acl`. The UAC-elevated repair always names a
machine-wide interpreter (a system PowerShell 7, else System32's 5.1), never a PATH lookup or a
per-user portable install.

## License

MIT
