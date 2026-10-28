import type { Translate } from './settings';

// Every label the backup pages show. Each is a row in the copy table, editable under Settings, Labels and copy.
const STEPS = ['waiting', 'database', 'locking', 'ready', 'unlocking', 'updating', 'secrets', 'certificate', 'restored', 'uploading', 'restarting'];
const ERRORS = ['failed', 'timeout', 'passphrase_too_short', 'passphrases_differ', 'no_file', 'wrong_origin', 'admin_only', 'backups_not_available',
  'backup_service_not_running', 'upload_too_large', 'upload_failed', 'no_upload', 'passphrase_missing', 'not_confirmed', 'wrong_code',
  'too_many_requests', 'sign_in_required', 'wrong_passphrase', 'not_a_backup', 'newer_format', 'newer_version', 'damaged', 'bad_name'];
const LABELS = ['passphrase', 'passphrase_hint', 'passphrase_again', 'make', 'made', 'download', 'file', 'confirm', 'confirm_hint', 'restore',
  'restored', 'sign_in', 'code'];

export function backupText(t: Translate): Record<string, string> {
  const keys = [...LABELS.map((k) => `backups.${k}`), ...STEPS.map((k) => `backups.step.${k}`), ...ERRORS.map((k) => `backups.error.${k}`)];
  return Object.fromEntries(keys.map((k) => [k, t(k)]));
}
