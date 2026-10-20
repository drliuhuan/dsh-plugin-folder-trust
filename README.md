# dsh-plugin-folder-trust

Windows-only DeepSeek Harness plugin. When a workspace folder is added, it asks once whether to
trust it, then grants the NTFS rights DSH's workspace-write sandbox needs -- including pushing the
capability grant and the Low integrity label through folders that already exist. Starting, quitting
and repairing show live progress; the composer and Settings list every workspace's permission state.

See [README.zh.md](README.zh.md) for the full design notes (Chinese).

## Install

    dsh plugin install dsh-plugin-folder-trust

## License

MIT
