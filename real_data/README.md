# Real telemetry samples

Real Sysmon and Security events recorded while attacks were emulated in a lab, converted by `irforge import-otrf`.

- Source: OTRF Security-Datasets, https://github.com/OTRF/Security-Datasets
- Licence: MIT, (c) 2021 Open Threat Research Forge (Mordor project).
- Not synthetic, but not from any company, bank or customer either. They come from OTRF's own lab.
- Only events irforge understands are kept (Sysmon 1, 3, 10, 11, 13, 22; Security 4624, 4625, 4688).
- `schtasks_persistence` (about 15k events) is not committed: `python -m irforge import-otrf --dataset schtasks_persistence --out real_data/schtasks_persistence.csv`.

| File | Emulated attack |
|------|-----------------|
| mimikatz_logonpasswords | Mimikatz logonpasswords via Empire |
| lsass_dump_comsvcs | LSASS dump with comsvcs.dll |
| dcsync_drsuapi | DCSync |
| run_key_persistence | Run key persistence |
| regsvr32_sct_launcher | regsvr32 remote scriptlet |
| mshta_vbscript_psh | mshta VBScript |
| bitsadmin_download | BITS download |
