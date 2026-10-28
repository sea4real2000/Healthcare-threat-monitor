"""The backup pages in a real browser, as people use them.

    python3 scripts/backup_ui_check.py make    BASE_URL SESSION_TOKEN PASSPHRASE OUT_FILE
    python3 scripts/backup_ui_check.py restore BASE_URL SETUP_CODE    PASSPHRASE BACKUP_FILE

make:    an administrator makes a backup with clicks and downloads it.
restore: on a new installation nobody has set up, the first visit page restores the backup with the setup code.
Called by scripts/backup_smoke.sh. Needs Python Playwright with Chromium. Exits with an error on failure.
"""
import sys

from playwright.sync_api import sync_playwright

mode, base, secret, passphrase, path = sys.argv[1:6]


def restore():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_context(ignore_https_errors=True).new_page()
        page.set_default_timeout(120000)
        page.goto(f'{base}/', wait_until='domcontentloaded')
        assert page.url.endswith('/welcome'), page.url
        page.get_by_role('link', name='Restore its backup instead').click()
        page.wait_for_url(lambda url: url.endswith('/welcome/restore'))
        page.fill('input[name=code]', secret)
        page.set_input_files('input[name=file]', path)
        page.fill('input[name=passphrase]', passphrase)
        page.fill('input[name=confirm]', 'RESTORE')
        page.get_by_role('button', name='Restore the backup').click()
        # The console starts again part way through, and the page keeps following the restore.
        page.wait_for_selector('[data-backup-state=done], [data-backup-state=failed]', timeout=900000)
        state = page.inner_text('[role=status]')
        assert page.locator('[data-backup-state=done]').count() == 1, state
        assert page.get_by_role('link', name='Sign in').is_visible()
        browser.close()
    print('PASS: a new installation restores a backup with clicks from its first visit page, in a real browser')


if mode == 'restore':
    restore()
    sys.exit(0)
token, out = secret, path
host = base.split('://', 1)[1].split('/', 1)[0]
with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(ignore_https_errors=True, accept_downloads=True)
    ctx.add_cookies([{'name': 'htm_session', 'value': token, 'domain': host.split(':')[0], 'path': '/', 'secure': True, 'httpOnly': True}])
    page = ctx.new_page()
    page.set_default_timeout(120000)
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.on('console', lambda m: errors.append(m.text) if m.type == 'error' else None)
    page.goto(f'{base}/console/settings/backups', wait_until='domcontentloaded')
    assert page.get_by_role('heading', name='Make a backup').is_visible(), page.inner_text('main')[:500]
    assert 'not running' not in page.inner_text('main'), 'the page says the backup service is not running'
    # Two different passphrases are refused in the browser, before anything is sent.
    page.locator('input[name=passphrase]').first.fill(passphrase)
    page.locator('input[name=confirm]').first.fill(passphrase + ' x')
    page.get_by_role('button', name='Make the backup').click()
    page.wait_for_selector('[data-backup-state=failed]')
    assert 'not the same' in page.inner_text('[data-backup-state=failed]')
    page.locator('input[name=confirm]').first.fill(passphrase)
    page.get_by_role('button', name='Make the backup').click()
    link = page.wait_for_selector('[data-backup-download]')
    with page.expect_download() as d:
        link.click()
    d.value.save_as(out)
    assert open(out, 'rb').read(10) == b'HTMBACKUP\n', 'the download is not a backup file'
    # The finished backup is listed for download when the page is opened again.
    page.goto(f'{base}/console/settings/backups', wait_until='domcontentloaded')
    assert page.locator('a[href^="/api/backups/"]').count() >= 1, 'the finished backup is not listed'
    assert page.get_by_role('heading', name='Restore a backup').is_visible()
    real = [e for e in errors if 'favicon' not in e]
    assert not real, f'errors in the browser: {real[:5]}'
    browser.close()
print('PASS: an administrator makes and downloads a backup with clicks in a real browser')
