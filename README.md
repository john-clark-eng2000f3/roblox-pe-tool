# roblox_pe

Small CLI tool I wrote to inspect Roblox Studio and Player Windows binaries (`RobloxStudioBeta.exe`, `RobloxPlayerBeta.exe`), check section changes between builds, and grab compiler/linker timestamps.

## Install

```bash
pip install -e .
```

## Usage

Inspect a local binary:
```bash
roblox-pe inspect RobloxPlayerBeta.exe
roblox-pe inspect RobloxStudioBeta.exe --json
```

Diff sections and exported hashes between two versions:
```bash
roblox-pe diff old/RobloxStudioBeta.exe new/RobloxStudioBeta.exe
```

Dump known function signatures or section hashes:
```bash
roblox-pe signatures RobloxStudioBeta.exe --out sigs.json
```

Fetch client metadata or manifest info from Roblox setup CDN:
```bash
roblox-pe fetch version-abcdef1234567890 --channel LIVE
```

<!-- checked: 2026-09-24 -->
