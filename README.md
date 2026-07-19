# dota-plus-unlocker

A tiny internal dll that unlocks Dota Plus locally. It simply hooks the account status function inside `client.dll` using MinHook.

### How it works
* Scans `.text` section of `client.dll` using a hardcoded pattern to find `GetProtoCDOTAGameAccountPlus`.
* Forces `m_nStatus` to `1` (`STATUS_SUBSCRIBED`).
* Writes debug logs to `C:\dota-plus-unlocker\log.txt` so you can check if the hook actually placed.
* Has a `ManualMap` export, making it fully ready for manual map injection.

Built purely for fun and reverse engineering research.

Highly recommend compiling from source to reduce ban risk. Use at your own risk.
