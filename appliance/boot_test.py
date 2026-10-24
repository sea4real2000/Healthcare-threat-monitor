"""Starts the built appliance in QEMU and goes through what a hospital does, with clicks and typing only.

    python3 appliance/boot_test.py vm  <disk.raw>   [bios|uefi]
    python3 appliance/boot_test.py usb <usb.raw>    [bios|uefi]

vm:  starts the virtual machine disk, waits for the address and setup code on its screen, then in a real
     browser enters the code, chooses a password, sets up the sign in app and reaches the console.
usb: starts a computer from the USB installer (attached as a real USB stick) with an empty disk, types the
     disk number and ERASE as a person would, then removes the stick, restarts from the disk and does the above.

uefi uses firmware with Secure Boot switched on and Microsoft's keys, as on most hospital computers.
Needs qemu-system-x86, ovmf and Python Playwright. The browser reaches the guest through a small proxy in
this script, so it uses the guest's own address as a person on the hospital network would.
Works without KVM, slowly. Not part of any installation.
"""
import base64, hashlib, hmac, json, os, re, shutil, socket, struct, subprocess, sys, tempfile, time

MODE, DISK = sys.argv[1], sys.argv[2]
FIRMWARE = sys.argv[3] if len(sys.argv) > 3 else 'bios'
GUEST_NET, GUEST_IP = '192.168.76.0/24', '192.168.76.15'   # QEMU gives the guest the 15th address
FORWARDS = {443: 18443, 80: 18080}   # the guest's port, and the port on this computer that reaches it
PROXY_PORT = 18128
BOOT_TIMEOUT = int(os.environ.get('BOOT_TIMEOUT', '5400'))
KVM = os.path.exists('/dev/kvm') and os.access('/dev/kvm', os.W_OK)
TIMEOUT_MS = 60000 if KVM else 600000
KEEP = os.environ.get('KEEP_WORK')   # keep the disks and serial logs afterwards, to look into a failure
work = tempfile.mkdtemp(prefix='htm-boot-')
fails = []


def ok(name, cond, detail=''):
    print(('PASS ' if cond else 'FAIL ') + name + ('' if cond or not detail else f'  [{detail}]'), flush=True)
    if not cond:
        fails.append(name)


def qemu(disks, serial_log, usb=None):
    """disks: list of raw files attached as SATA disks. usb: a raw file attached as a USB stick."""
    cmd = ['qemu-system-x86_64', '-m', '4096', '-smp', '2', '-display', 'none', '-vga', 'std',
           '-serial', f'file:{serial_log}', '-qmp', f'unix:{work}/qmp,server,nowait',
           '-netdev', f'user,id=n0,net={GUEST_NET},' + ','.join(f'hostfwd=tcp:127.0.0.1:{h}-:{g}' for g, h in FORWARDS.items()),
           '-device', 'e1000,netdev=n0']
    cmd += ['-accel', 'kvm', '-cpu', 'host'] if KVM else ['-accel', 'tcg', '-cpu', 'max']
    if FIRMWARE == 'uefi':
        vars_copy = f'{work}/vars.fd'
        shutil.copy('/usr/share/OVMF/OVMF_VARS_4M.ms.fd', vars_copy)
        cmd += ['-machine', 'q35,smm=on', '-global', 'driver=cfi.pflash01,property=secure,value=on',
                '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
                '-drive', f'if=pflash,format=raw,unit=1,file={vars_copy}']
    else:
        cmd += ['-machine', 'q35']
    cmd += ['-device', 'ahci,id=ahci']
    for i, d in enumerate(disks):
        cmd += ['-drive', f'if=none,id=d{i},format=raw,file={d}', '-device', f'ide-hd,drive=d{i},bus=ahci.{i}']
    if usb:
        cmd += ['-device', 'qemu-xhci,id=xhci', '-drive', f'if=none,id=stick,format=raw,file={usb}',
                '-device', 'usb-storage,bus=xhci.0,drive=stick,bootindex=0']
    print('starting:', 'KVM' if KVM else 'no KVM, this is slow', FIRMWARE, flush=True)
    return subprocess.Popen(cmd)


def start_proxy():
    """The browser asks for the guest's own address, exactly as a person on the network would, and this hands
    the connection to QEMU's forwarded port. Only the guest's address is passed on."""
    import threading

    def pipe(a, b):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                b.sendall(data)
        except OSError:
            pass
        finally:
            for x in (a, b):
                try:
                    x.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(client):
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = client.recv(4096)
            if not chunk:
                client.close(); return
            head += chunk
        line = head.split(b'\r\n', 1)[0].decode()
        m = re.match(r'CONNECT ([0-9.]+):(\d+) ', line)
        if not m or m.group(1) != GUEST_IP or int(m.group(2)) not in FORWARDS:
            client.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n'); client.close(); return
        upstream = socket.create_connection(('127.0.0.1', FORWARDS[int(m.group(2))]))
        client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()

    server = socket.socket(); server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', PROXY_PORT)); server.listen(64)
    def serve():
        while True:
            threading.Thread(target=handle, args=(server.accept()[0],), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()


def wait_serial(log, pattern, timeout, proc):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return None
        text = open(log, errors='replace').read() if os.path.exists(log) else ''
        m = re.search(pattern, text)
        if m:
            return m
        time.sleep(5)
    return None


KEYS = {' ': 'spc', '\n': 'ret'}


def type_text(text):
    s = socket.socket(socket.AF_UNIX); s.connect(f'{work}/qmp'); f = s.makefile('rw')
    f.readline(); f.write(json.dumps({'execute': 'qmp_capabilities'}) + '\n'); f.flush(); f.readline()
    for ch in text:
        key = KEYS.get(ch) or (f'shift-{ch.lower()}' if ch.isupper() else ch)
        f.write(json.dumps({'execute': 'human-monitor-command', 'arguments': {'command-line': f'sendkey {key}'}}) + '\n'); f.flush(); f.readline()
        time.sleep(0.15)
    s.close()


def stop(proc):
    proc.terminate()
    try:
        proc.wait(60)
    except subprocess.TimeoutExpired:
        proc.kill()


def totp(secret):
    s = secret.replace(' ', ''); key = base64.b32decode(s + '=' * (-len(s) % 8))
    mac = hmac.new(key, struct.pack('>Q', int(time.time() // 30)), hashlib.sha1).digest(); o = mac[-1] & 15
    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7fffffff) % 1000000:06d}"


def first_visit(base, code):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(proxy={'server': f'http://127.0.0.1:{PROXY_PORT}'})
        ctx = b.new_context(ignore_https_errors=True)
        # Without KVM every page is slow, so wait longer than a browser would on real hardware.
        ctx.set_default_timeout(TIMEOUT_MS)
        pg = ctx.new_page()
        pg.goto(base + '/'); ok('the first visit goes straight to setting up the administrator', pg.url.endswith('/welcome'), pg.url)
        pg.fill('input[name=code]', 'ABCDE FGHJK'); pg.fill('input[name=name]', 'Ada Obi'); pg.fill('input[name=email]', 'ada@hospital.example')
        pg.click('button[type=submit]'); pg.wait_for_url('**error=code**')
        ok('a wrong setup code is refused', 'does not match' in pg.inner_text('main'))
        pg.fill('input[name=code]', code.replace(' ', '').lower()); pg.fill('input[name=name]', 'Ada Obi'); pg.fill('input[name=email]', 'ada@hospital.example')
        pg.click('button[type=submit]'); pg.wait_for_url('**/setup?token=**')
        pw = 'ward seven lantern quiet 2026'
        pg.fill('input[name=password]', pw); pg.fill('input[name=confirm]', pw); pg.click('button[type=submit]'); pg.wait_for_selector('img.qr')
        sec = re.search(r'into the app: ([A-Z2-7 ]+)', pg.inner_text('body')).group(1).strip()
        pg.fill('input[name=code]', totp(sec)); pg.click('button[type=submit]'); pg.wait_for_url('**/console/**')
        ok('the administrator reaches the console with the code from the screen, nothing typed in a terminal', '/console' in pg.url, pg.url)
        pg.goto(base + '/console/sources/windows')
        ok('the Windows page offers the certificate authority for browsers', pg.locator('a[href="/api/trust/root"]').count() == 1)
        root = pg.request.get(base + '/api/trust/root')
        pem = root.text() if root.ok else ''
        with open(f'{work}/root.crt', 'w') as f:
            f.write(pem)
        # --noproxy '' so the address is not skipped by a no_proxy setting on this computer.
        trusted = subprocess.run(['curl', '-sf', '--noproxy', '', '--proxy', f'http://127.0.0.1:{PROXY_PORT}', '--cacert', f'{work}/root.crt', f'{base}/api/health'], capture_output=True)
        ok('browsers that trust the downloaded certificate authority trust the installation, with no warning',
           'BEGIN CERTIFICATE' in pem and trusted.returncode == 0, f'curl exit {trusted.returncode}')
        # And the same check refuses an authority that is not this installation's, so it proves something.
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
                        '-subj', '/CN=Some other authority', '-keyout', f'{work}/other.key', '-out', f'{work}/other.crt'], capture_output=True, check=True)
        other = subprocess.run(['curl', '-sf', '--noproxy', '', '--proxy', f'http://127.0.0.1:{PROXY_PORT}', '--cacert', f'{work}/other.crt', f'{base}/api/health'], capture_output=True)
        ok('a browser trusting some other authority still gets the warning', other.returncode == 60, f'curl exit {other.returncode}')
        anon_ctx = b.new_context(ignore_https_errors=True); anon_ctx.set_default_timeout(TIMEOUT_MS)
        anon = anon_ctx.new_page()
        anon.goto(base + '/welcome'); ok('then the setup page is closed', anon.url.endswith('/signin'), anon.url)
        ok('the certificate authority is not offered to someone not signed in', anon.request.get(base + '/api/trust/root').status == 401)
        b.close()


def appliance_check(disk, label):
    log = f'{work}/{label}.serial'
    proc = qemu([disk], log)
    try:
        m = wait_serial(log, r'https://(\d+\.\d+\.\d+\.\d+)', BOOT_TIMEOUT, proc)
        ok(f'{label}: the screen shows the address to open', bool(m) and m.group(1) == GUEST_IP, m.group(1) if m else 'nothing')
        m = wait_serial(log, r'Setup code:\s+([A-Z0-9]{5} [A-Z0-9]{5})', BOOT_TIMEOUT, proc)
        ok(f'{label}: the screen shows the setup code', bool(m))
        if not m:
            print(open(log, errors='replace').read()[-4000:])
            return
        text = open(log, errors='replace').read()
        ok(f'{label}: the screen says it is running', 'Running.' in text)
        grown = re.search(r'htm-firstboot: file system fills the partition: (\d+(?:\.\d+)?)G', text)
        ok(f'{label}: on its first start the system grew to fill its 24 GB disk', bool(grown) and float(grown.group(1)) > 20,
           grown.group(0) if grown else re.findall(r'htm-firstboot: .*', text)[:3])
        seen = len(text)
        first_visit(f'https://{GUEST_IP}', m.group(1))
        # The screen changes within a few seconds: still running, and the code and its password hint gone.
        after = None
        for _ in range(60):
            after = re.search(r'Running\.(?:(?!Setup code|password the setup code)[\s\S])*?Maintenance: press Alt and F2 and sign in as htm\.',
                              open(log, errors='replace').read()[seen:])
            if after:
                break
            time.sleep(5)
        ok(f'{label}: once set up, the screen no longer shows the code', bool(after))
    finally:
        stop(proc)


start_proxy()
try:
    if MODE == 'vm':
        if os.environ.get('IN_PLACE'):
            disk = DISK   # a disk kept from an earlier run, to look into a failure without preparing it again
        else:
            disk = f'{work}/vm.raw'
            subprocess.run(['cp', '--sparse=always', DISK, disk], check=True)
            os.truncate(disk, 24 * 1024 ** 3)   # a bigger disk than the image, as the OVA and VHDX give
        appliance_check(disk, 'virtual machine')
    else:
        stick, target = f'{work}/usb.raw', f'{work}/target.raw'
        subprocess.run(['cp', '--sparse=always', DISK, stick], check=True)
        open(target, 'wb').close(); os.truncate(target, 24 * 1024 ** 3)
        log = f'{work}/installer.serial'
        proc = qemu([target], log, usb=stick)
        try:
            m = wait_serial(log, r'htm-installer: waiting for a disk number, ([^\r\n]+)', BOOT_TIMEOUT, proc)
            ok('the USB stick starts the installer, which lists the computer\'s one disk and not the stick itself',
               bool(m) and len(m.group(1).split()) == 1, m.group(0) if m else open(log, errors='replace').read()[-3000:])
            if m:
                type_text('1\n')
                m = wait_serial(log, r'htm-installer: waiting for ERASE to install on (\S+)', 300, proc)
                ok('choosing the disk asks for ERASE before anything is erased', bool(m))
                type_text('ERASE\n')
                m = wait_serial(log, r'htm-installer: (installed on \S+|failed: [^\r\n]+)', BOOT_TIMEOUT, proc)
                ok('the platform is copied to the disk', bool(m) and m.group(1).startswith('installed'), m.group(1) if m else 'nothing')
                ok('the USB stick itself is unchanged, so it can install the next computer',
                   subprocess.run(['cmp', '-s', DISK, stick]).returncode == 0)
        finally:
            stop(proc)
        if not fails:
            appliance_check(target, 'installed computer')
finally:
    if KEEP:
        print('kept', work)
    else:
        shutil.rmtree(work, ignore_errors=True)
print('ALL PASSED' if not fails else f'{len(fails)} failed: ' + '; '.join(fails))
sys.exit(1 if fails else 0)
