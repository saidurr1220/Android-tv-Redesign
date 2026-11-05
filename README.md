# Android TV Redesign

`tvtool.py` finds Android TV / Google TV devices on your local network and
applies reversible speed tweaks over ADB.

Run it on a computer connected to the **same network** as the TV
(guest Wi-Fi networks often block device-to-device traffic).

## Requirements

- Python 3.8+ (discovery uses only the standard library)
- [Android platform-tools](https://developer.android.com/tools/releases/platform-tools) (`adb`) for `info`, `optimize` and `restore`

## 1. Find the TV

```sh
python3 tvtool.py discover
```

Discovery runs two methods together:

1. **mDNS** queries for services Android TVs usually advertise
   (`_androidtvremote2._tcp`, `_googlecast._tcp`, `_adb-tls-connect._tcp`, ...).
2. A **parallel port scan** of your `/24` subnet for ADB (5555) and the
   Android TV remote ports (6466/6467). This covers TVs that don't answer mDNS.

Use `--subnet 10.0.0.0/24` to scan a different range or `--mdns-only` to skip the scan.

### Samsung TVs

Samsung TVs run Tizen, not Android, so the ADB steps below do not apply to
them. `discover` also finds them: it listens for Samsung SSDP replies and
checks port 8001, where most 2016+ Samsung TVs answer `/api/v2/` with the
model name and power state. Use `--no-samsung` to skip this check. Some
models or network setups don't answer; if yours is missing, check the
TV's IP under Settings > General > Network > Network Status.

## 2. Enable network debugging on the TV

Settings > Device Preferences > About > press **Build** 7 times, then
Developer options > enable **USB debugging** (and **Network debugging** /
**Wireless debugging** if your TV has it). Accept the "Allow debugging?"
prompt on the TV the first time you connect. Menu names vary by brand.

## 3. Make it faster

```sh
python3 tvtool.py info 192.168.1.50
python3 tvtool.py optimize 192.168.1.50                    # animations at 0.5x
python3 tvtool.py optimize 192.168.1.50 --animation-scale 0 # animations off
python3 tvtool.py optimize 192.168.1.50 --compile           # also AOT-compile apps
python3 tvtool.py optimize 192.168.1.50 --disable com.example.bloatapp
```

`optimize` saves the original settings to `.tvtool_state.json`. Undo everything with:

```sh
python3 tvtool.py restore 192.168.1.50
```

Only disable packages you recognise. `--disable` refuses packages on a
protected list (Google Play services, launchers, System UI, setup, keyboard,
HDMI/tuner inputs), taken from the "never turn off" list in
[tv-detox](https://github.com/Ansub/tv-detox). The list is not complete for
every brand, so if you are unsure, leave a package enabled.

## 4. Redesign the home screen with tv-detox

[tv-detox](https://github.com/Ansub/tv-detox) (MIT) installs a minimal
launcher (your apps, HDMI inputs, a clock) and has a more thorough debloat
guide. It needs the TV's address, which `discover` gives you:

```sh
python3 tvtool.py discover                 # note the TV's IP
git clone https://github.com/Ansub/tv-detox
sh tv-detox/install.sh 192.168.1.50        # undo: sh tv-detox/undo.sh 192.168.1.50
```

On Google TV / Chromecast with Google TV, read tv-detox's warnings first:
do not turn off `com.google.android.apps.tv.launcherx`.

## 5. Turn debugging off afterwards

While USB, Network or Wireless debugging is on, other devices on your
network can ask to control the TV. Turn it off in Developer options once
you are done, and back on only to run `restore` or `undo.sh`.
