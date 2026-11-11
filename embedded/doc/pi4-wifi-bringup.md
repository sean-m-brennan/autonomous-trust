# Raspberry Pi 4 on Wi-Fi: bring-up and mixed-fleet check

This brings a Raspberry Pi 4 up as an AutonomousTrust node on the home Wi-Fi
network and verifies, from the development host, that it forms one cohort with
several AT nodes running on the host.

The host nodes run in network namespaces with ipvlan links on the host's
`wlan0` (`embedded/wifi-fleet.sh`). AT discovers peers by broadcast and
multicast on the local segment, so every node needs an address on the Wi-Fi
subnet itself. A Wi-Fi client link cannot be bridged into a VM and cannot carry
macvlan, because the access point drops frames from MAC addresses that never
associated with it. ipvlan shares `wlan0`'s MAC and gives each namespace its
own IP, which the access point accepts.

The steps below run the Pi on Raspberry Pi OS Lite, because steps 4, 5 and
10 need a shell on it over SSH. The hardened Buildroot image
(`embedded/buildroot/`) has no SSH server. It does have Ethernet and Wi-Fi, and
it can stand in for the Pi once the plan has worked on Pi OS; see "Using the
hardened image" at the end.

Values used below:

| Name | Value |
|---|---|
| Wi-Fi network | the home SSID; the host's `wlan0` is on 172.27.3.0/24, gateway 172.27.3.1 |
| Pi hostname / user | `at-pi` / `at` |
| Pi address | `PI=172.27.3.x`, whatever the router leases it (reserve it, step 3) |
| Host node addresses | 172.27.3.201 upward, by default; must be outside the router's DHCP pool |
| AT ports | UDP 27787 (discovery and peer traffic), 27788 (encrypted group channel) |

## 1. Build matching binaries from one commit

The Pi and the host nodes must speak the same wire protocol, so build both
architectures from one commit. The binaries in `embedded/dist/` are months old
and from different commits (amd64 April, arm64 June). Build in a clean worktree,
because the working checkout may hold uncommitted changes under `src/c/`.

The arm64 build runs under QEMU user emulation. This host has no `aarch64`
binfmt handler registered, so install one first:

```bash
sudo apt install qemu-user-static binfmt-support
```

```bash
git -C ~/Software/continuous-space/lib/muudd/lib/autonomous_trust worktree add ~/Software/continuous-space/lib/muudd/lib/at-pi-build HEAD
```

```bash
~/Software/continuous-space/lib/muudd/lib/at-pi-build/embedded/build-arm.sh --static --all-arch
```

The tarballs land in `~/Software/continuous-space/lib/muudd/lib/at-pi-build/embedded/dist/`:
`autonomous-trust-arm64-static.tar.gz` for the Pi and
`autonomous-trust-amd64-static.tar.gz` for the host nodes. Record the commit
(`git -C ~/Software/continuous-space/lib/muudd/lib/at-pi-build rev-parse --short HEAD`)
with any results.

## 2. Write the SD card

Install Raspberry Pi Imager on the host from Flathub (Debian 12 does not
package it):

```bash
flatpak install flathub org.raspberrypi.rpi-imager
```

Run it with `flatpak run org.raspberrypi.rpi-imager`, choose Raspberry Pi 4 as
the device, and write **Raspberry Pi OS Lite (64-bit)** to a microSD card of 8 GB or more. In
the imager's OS customisation, set:

- hostname `at-pi`;
- user `at` with a password;
- wireless LAN: the home SSID and password, wireless country `US`;
- locale and time zone;
- Services: enable SSH, public-key authentication only, with
  `~/.ssh/id_ed25519.pub`.

## 3. First boot and find the Pi

Insert the card, power the Pi with a 5 V / 3 A USB-C supply, and allow about
two minutes for first boot.

```bash
ping -c 3 at-pi.local
```

If mDNS does not resolve, find the Pi in the router's client list, or scan:
`ip neigh show dev wlan0` after `ping -b -c 2 172.27.3.255`. Then reserve its
address in the router's DHCP settings so that it stays fixed, and set it for
the rest of this plan:

```bash
export PI=172.27.3.x
```

```bash
ssh at@$PI
```

## 4. Prepare the Pi

On the Pi:

```bash
sudo apt update && sudo apt full-upgrade -y
```

Check that the clock is synchronised, since AT timestamps and signs its
messages (`System clock synchronized: yes`):

```bash
timedatectl
```

Turn off Wi-Fi power saving. The Pi's Broadcom radio sleeps between beacons
and then misses broadcast and multicast frames, which is how AT finds peers.
The imager names the Wi-Fi connection `preconfigured`:

```bash
sudo nmcli connection modify preconfigured 802-11-wireless.powersave 2 && sudo nmcli connection up preconfigured
```

```bash
iw dev wlan0 get power_save
```

The output should be `Power save: off`. Make sure `wlan0` is the Pi's only
configured interface (`ip -br addr`). AT takes the first non-loopback IPv4
address it finds, so leave the Ethernet port unplugged.

## 5. Install AT on the Pi

From the host:

```bash
scp ~/Software/continuous-space/lib/muudd/lib/at-pi-build/embedded/dist/autonomous-trust-arm64-static.tar.gz ~/Software/continuous-space/lib/muudd/lib/at-pi-build/embedded/install.sh ~/Software/continuous-space/lib/muudd/lib/at-pi-build/embedded/autonomous-trust.service at@$PI:
```

On the Pi:

```bash
sudo ./install.sh --tarball autonomous-trust-arm64-static.tar.gz && sudo systemctl start autonomous-trust
```

```bash
journalctl -u autonomous-trust -f
```

The node generates its identity on first start, in
`/opt/autonomous-trust/etc/at/`. Check that it chose `wlan0`'s address:

```bash
cat /opt/autonomous-trust/etc/at/network.cfg.json
```

`ip4_cidr` must be the Pi's Wi-Fi address with its prefix, such as
`172.27.3.x/24`.

## 6. Check that the host hears the Pi

On the host, watch for AT frames from the Pi:

```bash
sudo tcpdump -ni wlan0 host $PI and udp portrange 27787-27788
```

A lone node announces itself periodically, so frames to the subnet broadcast
or to the multicast group (239.x.x.x) should appear within a minute. If the Pi's
own `tcpdump` (`sudo apt install tcpdump`) shows them leaving but the host sees
nothing, the access point is not forwarding broadcast or multicast between
wireless clients. Turn off "AP isolation" or "client isolation" on the router,
and check that it does not filter multicast.

## 7. Start the host nodes

Check that the default host addresses are outside the router's DHCP pool, or
pass a free range with `--first-ip`. The script refuses an address that answers
ARP, but it cannot see a lease the router has issued to a device that is
switched off.

```bash
sudo ~/Software/continuous-space/lib/muudd/lib/autonomous_trust/embedded/wifi-fleet.sh up --nodes 4 --tarball ~/Software/continuous-space/lib/muudd/lib/at-pi-build/embedded/dist/autonomous-trust-amd64-static.tar.gz
```

Each node runs as a transient system unit, `at-wifi-node1` to `at-wifi-node4`,
under your own user, in namespace `atwifi1` to `atwifi4`. The units survive the
desktop session that started them.

ipvlan isolates the namespaces from `wlan0` itself: the host cannot ping its
own nodes, and they cannot reach the host. They reach the Pi and the rest of
the Wi-Fi network normally. Check them through `status`, the logs and
`tcpdump`, not by pinging them from the host.

## 8. Verify one cohort

Allow a minute or two for admission and group-key exchange, then:

```bash
~/Software/continuous-space/lib/muudd/lib/autonomous_trust/embedded/wifi-fleet.sh status --pi at@$PI
```

`status` reads each host node's `group.cfg.json` and, over SSH, the Pi's. It
passes when every unit is active, every node and the Pi report the same group
UUID, every group lists at least five members (four host nodes and the Pi), and
the Pi's group lists every host node's address. For one node's log:

```bash
sudo ~/Software/continuous-space/lib/muudd/lib/autonomous_trust/embedded/wifi-fleet.sh logs 1
```

To see the cohort's traffic on the air:

```bash
sudo tcpdump -ni wlan0 udp portrange 27787-27788
```

## 9. Exercise it

- **Pi leaves and returns.** On the Pi, `sudo systemctl stop autonomous-trust`.
  The host nodes' logs should record the Pi's presence lapsing. Start it again,
  and `status` should pass again with the same group UUID.
- **Pi reboots.** `sudo reboot` on the Pi. Its identity persists in
  `/opt/autonomous-trust/etc/at/`, so it rejoins as the same peer.
- **Host node leaves.** `sudo systemctl stop at-wifi-node2`, then check that the
  Pi's log records it lapsing.

## 10. Measure on the Pi

These are the first on-hardware figures, which Volume 5 §13.2 is missing. With
the cohort formed, on the Pi:

```bash
grep -e VmRSS -e VmHWM /proc/$(pidof at_demo)/status
```

```bash
top -b -d 15 -n 20 -p $(pidof at_demo) | grep at_demo
```

```bash
cat /sys/class/net/wlan0/statistics/rx_bytes /sys/class/net/wlan0/statistics/tx_bytes
```

Read the byte counters twice, a few minutes apart, to get the rate. The Docker
measurement on the host (16 and 32 nodes, x86) gave 33-54 MiB RSS, about 1% of
one core and about 9-21 kB/s each way per node, for comparison.

## 11. Tear down

```bash
sudo ~/Software/continuous-space/lib/muudd/lib/autonomous_trust/embedded/wifi-fleet.sh down
```

`down` stops the units and deletes the namespaces, which removes the ipvlan
links. The node identities stay in `embedded/.wifi-fleet/` and the next `up`
reuses them; `down --purge` deletes them. On the Pi,
`sudo systemctl disable --now autonomous-trust` stops AT.

## Using the hardened image

`embedded/build-image.sh` builds `embedded/dist/autonomous-trust.img`, the
Buildroot image with `at_demo` already installed and enabled. It brings up
Ethernet and Wi-Fi with DHCP, but it has no SSH server and no Wi-Fi
credentials, so you supply the network after flashing:

```bash
sudo ~/Software/continuous-space/lib/muudd/lib/autonomous_trust/embedded/flash.sh ~/Software/continuous-space/lib/muudd/lib/autonomous_trust/embedded/dist/autonomous-trust.img /dev/sdX
```

Mount the card's first (FAT) partition on the host, copy
`wpa_supplicant.conf.example` to `wpa_supplicant.conf` on the same partition,
and put in the SSID and passphrase. Keep Unix line endings. The Pi mounts this
partition read-only and readable by root only. Without the file, `wlan0`
stays down and the node uses Ethernet alone.

On boot the node gets an address by DHCP and starts AT on its own. If
Ethernet and Wi-Fi are both connected, AT binds whichever address it finds
first, so connect only the one you are testing. Check it from the host with
steps 6 to 8, leaving out `--pi`, since `status --pi` reads the Pi's config
over SSH. The host nodes' groups should list the Pi's address.

The kernel and systemd print their boot messages on an HDMI monitor, and
the green LED blinks a heartbeat while the kernel runs. The screen is output
only, since the image has no keyboard drivers. The kernel also logs to the
mini UART on GPIO 14 (TX) and 15 (RX), 115200 baud, through a 3.3 V
USB-serial adapter, from its first instructions on.
