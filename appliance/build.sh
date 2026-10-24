#!/bin/bash
# Builds the Healthcare Threat Monitor appliance: a ready made computer system with the platform inside, so a
# hospital installs it by importing a file or starting a computer from a USB stick, with no command typed.
#
#   sudo appliance/build.sh <output folder>
#
# Run from the repository root, on Ubuntu, as root, after the platform's images are built or pulled:
#   docker compose -f docker-compose.hospital.yml build
#   docker pull postgres:16-alpine && docker pull caddy:2
# The release workflow (.github/workflows/release.yml) does exactly this for each version.
#
# Makes, in the output folder:
#   healthcare-threat-monitor-<version>.ova            VirtualBox and VMware: File, Import Appliance
#   healthcare-threat-monitor-<version>-hyperv.zip     Hyper-V: a .vhdx disk to attach to a new virtual machine
#   healthcare-threat-monitor-<version>-usb.img.xz     USB installer, written to a stick with balenaEtcher or Rufus
#   SHA256SUMS                                         to check each download
#
# Needs: debootstrap, qemu-utils, gdisk, mtools, dosfstools, e2fsprogs, zstd, xz-utils, zip, grub-pc-bin.
# Every setting below can be changed with an environment variable of the same name.
set -euo pipefail

OUT=${1:?give the output folder}
SUITE=${SUITE:-noble}
MIRROR=${MIRROR:-http://archive.ubuntu.com/ubuntu}
WORK=${WORK:-$(mktemp -d /var/tmp/htm-appliance.XXXXXX)}   # set to the folder of a stopped build to reuse its system
DISK_GB=${DISK_GB:-64}            # the size the virtual machine's disk grows to; it only uses what it fills
VM_CPUS=${VM_CPUS:-2}
VM_MEMORY_MB=${VM_MEMORY_MB:-4096}
IMAGES=${IMAGES:-"healthcare-threat-monitor/tools:local healthcare-threat-monitor/console:local healthcare-threat-monitor/worker:local postgres:16-alpine caddy:2"}
FIRMWARE=${FIRMWARE:-"linux-firmware-realtek linux-firmware-intel-misc"}   # network card firmware for real computers; empty for none
KEEP_RAW=${KEEP_RAW:-}            # set to keep the raw disk images, for testing
KEEP_SYSTEM=${KEEP_SYSTEM:-}      # set to keep the prepared system, to build again quickly with WORK

REPO=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(sed -n 's/^  "version": "\(.*\)",$/\1/p' "$REPO/web/package.json")
NAME=healthcare-threat-monitor-$VERSION
ROOT=$WORK/root
mkdir -p "$OUT" "$ROOT"
OUT=$(cd "$OUT" && pwd)
step() { echo; echo "== $*"; }
cleanup() {
  for m in dev/pts dev proc sys; do umount -l "$ROOT/$m" 2>/dev/null || true; done
}
trap cleanup EXIT

mount_root() {
  mount --bind /dev "$ROOT/dev"; mount --bind /dev/pts "$ROOT/dev/pts"
  mount -t proc proc "$ROOT/proc"; mount -t sysfs sys "$ROOT/sys"
}
in_root() { chroot "$ROOT" env DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 "$@"; }

if [ -f "$WORK/system-ready" ]; then
  step "1 and 2. Reusing the system prepared in $WORK"
  mount_root
else
step "1. A minimal Ubuntu $SUITE system"
debootstrap --variant=minbase --include=ca-certificates,gnupg "$SUITE" "$ROOT" "$MIRROR"
cat > "$ROOT/etc/apt/sources.list" <<EOF
deb $MIRROR $SUITE main universe
deb $MIRROR $SUITE-updates main universe
deb $MIRROR $SUITE-security main universe
EOF
mount_root
# No services start while the system is being built.
printf '#!/bin/sh\nexit 101\n' > "$ROOT/usr/sbin/policy-rc.d"; chmod 755 "$ROOT/usr/sbin/policy-rc.d"
in_root apt-get update -q
in_root apt-get install -y -q --no-install-recommends \
  systemd systemd-sysv systemd-resolved systemd-timesyncd udev dbus kmod iproute2 iputils-ping \
  linux-image-virtual initramfs-tools \
  docker.io docker-compose-v2 \
  sudo curl zstd less nano cloud-guest-utils gdisk parted e2fsprogs dosfstools util-linux keyboard-configuration console-setup
KVER=$(ls "$ROOT/lib/modules" | sort -V | tail -1)
# Drivers for real computers' disks, USB sticks and network cards, and for VMware and Hyper-V.
in_root apt-get install -y -q --no-install-recommends "linux-modules-extra-$KVER"

step "2. Boot files, signed for Secure Boot"
mkdir -p "$WORK/debs"
(cd "$WORK/debs" && chroot "$ROOT" sh -c 'cd /tmp && apt-get download -q shim-signed grub-efi-amd64-signed grub-pc-bin' && mv "$ROOT"/tmp/*.deb .)
for d in "$WORK"/debs/*.deb; do dpkg-deb -x "$d" "$WORK/boot-files"; done
if [ -n "$FIRMWARE" ]; then in_root apt-get install -y -q --no-install-recommends $FIRMWARE; fi
in_root update-initramfs -u -k "$KVER"
touch "$WORK/system-ready"
fi
KVER=$(ls "$ROOT/lib/modules" | sort -V | tail -1)

step "3. The platform"
rm -rf "$ROOT/opt/htm"
install -d "$ROOT/opt/htm/bin" "$ROOT/opt/htm/docker" "$ROOT/opt/htm/images" "$ROOT/etc/htm"
install -m 755 "$REPO"/appliance/files/bin/* "$ROOT/opt/htm/bin/"
install -m 644 "$REPO/docker-compose.hospital.yml" "$ROOT/opt/htm/"
install -m 644 "$REPO/docker/Caddyfile" "$ROOT/opt/htm/docker/"
echo "$VERSION" > "$ROOT/opt/htm/VERSION"
# The list of images the first start must find in Docker before it starts the platform.
: > "$ROOT/opt/htm/images.list"
for image in $IMAGES; do
  echo "$image" >> "$ROOT/opt/htm/images.list"
  file=$(echo "$image" | tr '/:' '__').tar.zst
  echo "saving $image"
  docker image inspect "$image" >/dev/null
  docker save "$image" | zstd -q -T0 -10 -o "$ROOT/opt/htm/images/$file"
done
install -m 644 "$REPO"/appliance/files/systemd/*.service "$ROOT/etc/systemd/system/"
install -m 644 "$REPO"/appliance/files/network/*.network "$ROOT/etc/systemd/network/"
# Docker does not run while the system is a USB installer.
for unit in docker.service docker.socket containerd.service; do
  install -d "$ROOT/etc/systemd/system/$unit.d"
  printf '[Unit]\nConditionPathExists=!/etc/htm/installer\n' > "$ROOT/etc/systemd/system/$unit.d/htm.conf"
done
in_root systemctl enable systemd-networkd systemd-resolved systemd-timesyncd docker htm-firstboot htm htm-screen htm-installer
in_root systemctl mask systemd-networkd-wait-online.service
ln -sf /run/systemd/resolve/stub-resolv.conf "$ROOT/etc/resolv.conf"
echo htm > "$ROOT/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 htm\n' > "$ROOT/etc/hosts"
# The maintenance account. Its password is set from the setup code on the first start, and must be changed at first sign in.
in_root id htm >/dev/null 2>&1 || in_root useradd -m -s /bin/bash -G sudo,docker htm
in_root passwd -l htm
in_root passwd -l root
# Each copy makes its own identity on its first start.
: > "$ROOT/etc/machine-id"; rm -f "$ROOT/var/lib/dbus/machine-id"
rm -f "$ROOT/usr/sbin/policy-rc.d"
in_root apt-get clean
rm -rf "$ROOT"/var/lib/apt/lists/* "$ROOT"/tmp/* "$ROOT"/var/log/*.log
rm -f "$ROOT"/opt/htm/images/*.tar.zst.tmp
cleanup

step "4. The disk"
ROOT_UUID=$(cat /proc/sys/kernel/random/uuid)
ESP_ID=$(od -An -N4 -tx4 /dev/urandom | tr -d ' ' | tr a-f A-F)
ESP_UUID="${ESP_ID:0:4}-${ESP_ID:4:4}"
cat > "$ROOT/etc/fstab" <<EOF
UUID=$ROOT_UUID  /          ext4  errors=remount-ro  0 1
UUID=$ESP_UUID   /boot/efi  vfat  umask=0077,nofail  0 1
EOF
install -d "$ROOT/boot/efi" "$ROOT/boot/grub/i386-pc"
cp "$WORK"/boot-files/usr/lib/grub/i386-pc/* "$ROOT/boot/grub/i386-pc/"
cat > "$ROOT/boot/grub/grub.cfg" <<EOF
set timeout=1
set default=0
insmod part_gpt
insmod ext2
search --no-floppy --fs-uuid --set=root $ROOT_UUID
menuentry "Healthcare Threat Monitor $VERSION" {
  linux /boot/vmlinuz-$KVER root=UUID=$ROOT_UUID ro console=ttyS0,115200 console=tty1 net.ifnames=1 systemd.show_status=error
  initrd /boot/initrd.img-$KVER
}
EOF
# Root file system sized to what it holds plus room for the first start; it grows to fill the disk then.
used_mb=$(du -sm --apparent-size "$ROOT" | cut -f1)
ROOT_MB=$(( used_mb * 12 / 10 + 1536 ))
ESP_MB=256
DISK_MB=$(( 1 + 1 + ESP_MB + ROOT_MB + 1 ))
raw=$WORK/disk.raw
rm -f "$raw"; truncate -s "${DISK_MB}M" "$raw"
sgdisk -Z "$raw" >/dev/null
sgdisk -n 1:2048:+1M -t 1:ef02 -c 1:bios \
       -n 2:0:+${ESP_MB}M -t 2:ef00 -c 2:efi \
       -n 3:0:0 -t 3:8300 -c 3:htm "$raw" >/dev/null
start_of() { sgdisk -i "$1" "$raw" | sed -n 's/^First sector: \([0-9]*\).*/\1/p'; }
sectors_of() { sgdisk -i "$1" "$raw" | sed -n 's/^Partition size: \([0-9]*\) sectors.*/\1/p'; }

echo "root file system"
mkfs.ext4 -q -F -L htm -U "$ROOT_UUID" -d "$ROOT" "$WORK/root.ext4" "$(( $(sectors_of 3) / 2 ))k"
dd if="$WORK/root.ext4" of="$raw" bs=512 seek="$(start_of 3)" conv=notrunc,sparse status=none
rm "$WORK/root.ext4"

echo "UEFI boot partition"
esp=$WORK/esp.vfat
rm -f "$esp"; mkfs.vfat -C -F 32 -n EFI -i "$ESP_ID" "$esp" "$(( $(sectors_of 2) / 2 ))" >/dev/null
shim=""
# The copy signed by Microsoft, which computers with Secure Boot trust.
for candidate in shimx64.efi.signed.latest shimx64.efi.signed; do
  if [ -z "$shim" ] && [ -f "$WORK/boot-files/usr/lib/shim/$candidate" ]; then shim="$WORK/boot-files/usr/lib/shim/$candidate"; fi
done
[ -n "$shim" ] || { echo "the signed shim was not found"; exit 1; }
cat > "$WORK/grub-stub.cfg" <<EOF
search --no-floppy --fs-uuid --set=root $ROOT_UUID
set prefix=(\$root)/boot/grub
configfile \$prefix/grub.cfg
EOF
mmd -i "$esp" ::/EFI ::/EFI/BOOT ::/EFI/ubuntu
# The removable path, which every UEFI computer starts from without being told: shim first, which starts grub.
mcopy -i "$esp" "$shim" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$esp" "$WORK/boot-files/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed" ::/EFI/BOOT/grubx64.efi
mcopy -i "$esp" "$WORK/boot-files/usr/lib/shim/mmx64.efi" ::/EFI/BOOT/mmx64.efi
mcopy -i "$esp" "$WORK/grub-stub.cfg" ::/EFI/BOOT/grub.cfg
mcopy -i "$esp" "$WORK/grub-stub.cfg" ::/EFI/ubuntu/grub.cfg
dd if="$esp" of="$raw" bs=512 seek="$(start_of 2)" conv=notrunc status=none
rm "$esp"

echo "BIOS boot"
grub-mkimage -O i386-pc -d "$WORK/boot-files/usr/lib/grub/i386-pc" -o "$WORK/core.img" \
  -c "$WORK/grub-stub.cfg" -p /boot/grub biosdisk part_gpt ext2 search search_fs_uuid configfile normal linux
core_sectors=$(( ($(stat -c %s "$WORK/core.img") + 511) / 512 ))
[ "$core_sectors" -le 2048 ] || { echo "the BIOS boot program is larger than its partition"; exit 1; }
bios_lba=$(start_of 1)
# What grub-install does for BIOS computers, written out, so no loop device is needed:
# the first 440 bytes of boot.img go in the disk's first sector and point at core.img,
# and core.img's first sector lists where the rest of it is.
dd if="$WORK/boot-files/usr/lib/grub/i386-pc/boot.img" of="$raw" bs=440 count=1 conv=notrunc status=none
python3 - "$raw" "$WORK/core.img" "$bios_lba" "$core_sectors" <<'PY'
import struct, sys
raw, core, lba, n = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
with open(raw, 'r+b') as d:
    d.seek(0x5c); d.write(struct.pack('<Q', lba))          # boot.img: where core.img starts
    body = bytearray(open(core, 'rb').read())
    body[0x1f4:0x1fe] = struct.pack('<QH', lba + 1, n - 1)  # core.img: the rest, as one block list entry
    body[0x1fe:0x200] = struct.pack('<H', 0x820)            # loaded at segment 0x820
    d.seek(lba * 512); d.write(body)
PY
rm "$WORK/core.img"

step "5. The USB installer"
usb=$WORK/usb.raw
cp --sparse=always "$raw" "$usb"
# Same system, marked as an installer. debugfs writes into the file system without mounting it.
dd if="$usb" of="$WORK/usb-root.ext4" bs=512 skip="$(start_of 3)" count="$(sectors_of 3)" conv=sparse status=none
printf '[Journal]\nStorage=volatile\n' > "$WORK/journald.conf"
# The installer runs read only, so the stick never changes. The installed copy gets the usual settings back.
sed 's/  ext4  errors=remount-ro/  ext4  ro,errors=remount-ro/; s/  vfat  umask=0077,nofail/  vfat  ro,umask=0077,nofail/' "$ROOT/etc/fstab" > "$WORK/fstab.usb"
grep -q 'ext4  ro,' "$WORK/fstab.usb" || { echo "could not make the installer's fstab read only"; exit 1; }
debugfs -w "$WORK/usb-root.ext4" -f - >/dev/null <<EOF
write /dev/null /etc/htm/installer
write $ROOT/etc/fstab /etc/htm/fstab.installed
rm /etc/fstab
write $WORK/fstab.usb /etc/fstab
mkdir /etc/systemd/journald.conf.d
write $WORK/journald.conf /etc/systemd/journald.conf.d/htm-installer.conf
EOF
dd if="$WORK/usb-root.ext4" of="$usb" bs=512 seek="$(start_of 3)" conv=notrunc,sparse status=none
rm "$WORK/usb-root.ext4"
xz -T0 -6 -c "$usb" > "$OUT/$NAME-usb.img.xz"

step "6. Virtual machine files"
vm=$WORK/vm.raw
cp --sparse=always "$raw" "$vm"
truncate -s "${DISK_GB}G" "$vm"
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "$vm" "$WORK/$NAME-disk1.vmdk"
qemu-img convert -f raw -O vhdx -o subformat=dynamic "$vm" "$WORK/$NAME.vhdx"
capacity=$(( DISK_GB * 1024 * 1024 * 1024 ))
vmdk_size=$(stat -c %s "$WORK/$NAME-disk1.vmdk")
sed -e "s/@NAME@/$NAME/g" -e "s/@VERSION@/$VERSION/g" -e "s/@CAPACITY@/$capacity/g" -e "s/@VMDK_SIZE@/$vmdk_size/g" \
    -e "s/@CPUS@/$VM_CPUS/g" -e "s/@MEMORY@/$VM_MEMORY_MB/g" "$REPO/appliance/files/appliance.ovf" > "$WORK/$NAME.ovf"
(cd "$WORK" && {
  echo "SHA256($NAME.ovf)= $(sha256sum "$NAME.ovf" | cut -d' ' -f1)"
  echo "SHA256($NAME-disk1.vmdk)= $(sha256sum "$NAME-disk1.vmdk" | cut -d' ' -f1)"
} > "$NAME.mf")
# An OVA is a tar file with the description first.
(cd "$WORK" && tar --format=ustar -cf "$OUT/$NAME.ova" "$NAME.ovf" "$NAME.mf" "$NAME-disk1.vmdk")
(cd "$WORK" && rm -f "$OUT/$NAME-hyperv.zip" && zip -q -1 "$OUT/$NAME-hyperv.zip" "$NAME.vhdx")
rm -f "$WORK/$NAME-disk1.vmdk" "$WORK/$NAME.vhdx" "$WORK/$NAME.ovf" "$WORK/$NAME.mf"
if [ -n "$KEEP_RAW" ]; then mv "$raw" "$OUT/$NAME.raw"; mv "$usb" "$OUT/$NAME-usb.raw"; fi
rm -f "$vm" "$raw" "$usb"

(cd "$OUT" && sha256sum "$NAME.ova" "$NAME-hyperv.zip" "$NAME-usb.img.xz" > SHA256SUMS)
# KEEP_SYSTEM keeps the prepared system, so a later build with WORK set to this folder skips the slow steps.
if [ -n "$KEEP_SYSTEM" ]; then echo "kept the prepared system in $WORK"; else rm -rf "$ROOT" "$WORK"; fi
step "Done"
ls -l "$OUT"
