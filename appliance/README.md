# The appliance

A ready made computer system with Healthcare Threat Monitor inside, so a hospital installs it with clicks: import a virtual machine, or start a spare computer from a USB stick. Hospital staff should read [docs/hospital_install.md](../docs/hospital_install.md). This page is for people who build it.

## What is inside

- Ubuntu 24.04 LTS, minimal, with Docker and the Compose plugin from Ubuntu.
- The platform's images, saved into the system and loaded into Docker on the first start.
- `docker-compose.hospital.yml` and `docker/Caddyfile` in `/opt/htm`, unchanged from the repository.
- Boot files for both kinds of computer: BIOS, and UEFI with Secure Boot through Ubuntu's Microsoft signed shim.
- No SSH or other remote sign in. The `root` account is locked.

## What happens when it starts

| Part | File | What it does |
| --- | --- | --- |
| First start | `files/bin/htm-firstboot` | Once: grows the system to fill the disk it was given, and loads the images into Docker. |
| Platform | `files/bin/htm-start` | Every start: finds this computer's address, writes it to `/opt/htm/.env` as `HTM_HOSTNAME`, and starts the platform with Docker Compose. Notes when the address changed. |
| Screen | `files/bin/htm-screen` | On the computer's screen, refreshed every few seconds: the address to open, whether it is running, and the setup code until the first administrator is set up. Warns about VirtualBox's private network and a changed address. Sets the maintenance account's first password to the setup code. The same text goes to the serial console when it changes. |
| USB installer | `files/bin/htm-installer` | When `/etc/htm/installer` exists: lists the computer's disks, asks for a number and the word ERASE, copies itself to that disk, removes the installer mark from the copy, and asks to restart. Docker does not run in this mode. |

The services are in `files/systemd`, and every wired network card asks for an address with DHCP (`files/network`).

## Building

On Ubuntu, as root, from the repository root, once the images exist:

```bash
docker compose -f docker-compose.hospital.yml build
docker pull postgres:16-alpine && docker pull caddy:2
sudo appliance/build.sh dist
```

It makes `dist/healthcare-threat-monitor-<version>.ova`, `-hyperv.zip`, `-usb.img.xz` and `SHA256SUMS`. Every setting at the top of `build.sh` can be changed with an environment variable: the disk size, processors and memory of the virtual machine, the images, the Ubuntu mirror and the network card firmware. A stopped build can be resumed by setting `WORK` to its folder.

The disk is put together without mounting anything: the root file system with `mkfs.ext4 -d`, the UEFI partition with `mtools`, and the BIOS boot program written in place the way `grub-install` does. The USB installer is the same disk with the installer mark added by `debugfs`.

## Testing

```bash
sudo KEEP_RAW=1 appliance/build.sh dist
python3 appliance/boot_test.py vm  dist/healthcare-threat-monitor-<version>.raw bios
python3 appliance/boot_test.py usb dist/healthcare-threat-monitor-<version>-usb.raw uefi
```

The first starts the virtual machine disk in QEMU, reads the address and setup code from its serial console, and sets up the administrator in a real browser, which reaches the guest at its own address through a small proxy in the test. It also checks the disk grew, the certificate authority download, and that the code leaves the screen once used. The second starts a computer from the USB installer, attached as a USB stick, with Secure Boot on and Microsoft's keys, types the disk number and ERASE, then starts the installed disk and does the same. `.github/workflows/release.yml` runs both for every version before publishing it.
