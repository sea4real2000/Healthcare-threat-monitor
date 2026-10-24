import { describe, expect, it } from 'vitest';
import { normalize, NormalizeError, SOURCE_IDS } from '@/lib/normalize';

const NOW = Date.parse('2026-10-09T12:00:00Z');
const run = (source: string, payload: unknown) => normalize(source, payload, NOW);

describe('normalize', () => {
  it('knows all ten sources', () => {
    expect(SOURCE_IDS.sort()).toEqual(
      ['cloud', 'dns', 'edr', 'ehr', 'email', 'firewall', 'linux', 'medical_device', 'vpn', 'windows'].sort(),
    );
  });

  it('maps a firewall flow', () => {
    const e = run('firewall', {
      id: 'f1', ts: 1791547200000 - 31536000000, fw: 'FWCORE01', action: 'deny', proto: 'TCP', src: '10.20.1.14',
      spt: 51000, dst: '198.51.100.7', dpt: 8080, sent: 0, rcvd: 0, src_zone: 'clinical', dst_zone: 'internet', rule: 'r',
    });
    expect(e).toMatchObject({
      category: 'network_flow', action: 'flow_denied', outcome: 'failure', severity: 1,
      src_ip: '10.20.1.14', dst_ip: '198.51.100.7', dst_port: 8080, protocol: 'tcp',
    });
    expect(e.occurred_at).toBe('2025-10-09T12:00:00.000Z');
  });

  it('maps a VPN failure', () => {
    const e = run('vpn', { id: 'v1', time: '2026-10-09T11:00:00Z', event: 'auth_failed', user: 'JOkafor', client_ip: '198.51.100.9', country: 'US' });
    expect(e).toMatchObject({ category: 'session', action: 'vpn_auth_failed', outcome: 'failure', actor_user: 'jokafor' });
    expect(e.attributes.country).toBe('US');
  });

  it('maps an EDR file write', () => {
    const e = run('edr', {
      event_id: 'e1', timestamp: '2026-10-09T11:00:00Z', hostname: 'wsed001', event_type: 'file_write', user: 'abaker',
      process: { name: 'WINWORD.EXE', pid: 4242 }, file: { path: 'C:\\Users\\abaker\\Documents\\a.docx', ext: 'DOCX' },
    });
    expect(e).toMatchObject({ category: 'file', action: 'file_write', host: 'WSED001', actor_user: 'abaker' });
    expect(e.attributes).toMatchObject({ process_name: 'winword.exe', file_extension: 'docx' });
  });

  it('maps Windows logon success, failure and machine accounts', () => {
    const ok = run('windows', { RecordId: '9', TimeCreated: '2026-10-09T11:00:00Z', Computer: 'SRVDC01', EventID: 4624, Data: { TargetUserName: 'abaker', LogonType: 3, IpAddress: '10.20.1.11' } });
    expect(ok).toMatchObject({ source_event_id: 'SRVDC01:9', category: 'authentication', action: 'logon', outcome: 'success', src_ip: '10.20.1.11' });
    const bad = run('windows', { RecordId: '10', TimeCreated: '2026-10-09T11:00:00Z', Computer: 'WSED001', EventID: 4625, Data: { TargetUserName: 'abaker' } });
    expect(bad).toMatchObject({ outcome: 'failure', severity: 1 });
    const machine = run('windows', { RecordId: '11', TimeCreated: '2026-10-09T11:00:00Z', Computer: 'WSED001', EventID: 4624, Data: { TargetUserName: 'WSED001$' } });
    expect(machine.actor_user).toBeNull();
    const other = run('windows', { RecordId: '12', TimeCreated: '2026-10-09T11:00:00Z', Computer: 'WSED001', EventID: 4999, Data: {} });
    expect(other).toMatchObject({ category: 'windows', action: 'event_4999', outcome: 'unknown' });
  });

  it('reads the Windows events the collector sends', () => {
    const t = '2026-10-09T11:00:00Z';
    const proc = run('windows', { RecordId: '20', TimeCreated: t, Computer: 'WSED001.hospital.local', Channel: 'Security', EventID: 4688,
      Data: { SubjectUserName: 'abaker', TargetUserName: '-', NewProcessName: 'C:\\Windows\\System32\\vssadmin.exe',
        ParentProcessName: 'C:\\Windows\\System32\\cmd.exe', CommandLine: 'vssadmin delete shadows /all /quiet' } });
    expect(proc).toMatchObject({ source_event_id: 'WSED001:20', host: 'WSED001', category: 'process', action: 'process_start', actor_user: 'abaker' });
    expect(proc.attributes).toMatchObject({ process_name: 'vssadmin.exe', parent_name: 'cmd.exe', command_line: 'vssadmin delete shadows /all /quiet' });
    const service = run('windows', { RecordId: '20', TimeCreated: t, Computer: 'WSED001', Channel: 'System', EventID: 7036,
      Data: { param1: 'Volume Shadow Copy', param2: 'stopped' } });
    // The System log numbers its records separately, so its IDs cannot collide with the Security log's.
    expect(service).toMatchObject({ source_event_id: 'WSED001:sys:20', category: 'service' });
    expect(service.attributes).toMatchObject({ service_name: 'Volume Shadow Copy', service_state: 'stopped' });
    const added = run('windows', { RecordId: '21', TimeCreated: t, Computer: 'WSED001', EventID: 4732,
      Data: { SubjectUserName: 'tusman', TargetUserName: 'Administrators', MemberName: 'CN=abaker' } });
    expect(added).toMatchObject({ actor_user: 'tusman', action: 'group_member_added' });
    expect(added.attributes).toMatchObject({ group_name: 'Administrators' });
    const cleared = run('windows', { RecordId: '22', TimeCreated: t, Computer: 'WSED001', EventID: 1102, Data: { SubjectUserName: 'tusman' } });
    expect(cleared).toMatchObject({ category: 'defense_evasion', action: 'audit_log_cleared', severity: 3, actor_user: 'tusman' });
  });

  it('parses Linux syslog lines', () => {
    const base = { ts: '2026-10-09T11:00:00Z', host: 'srvehrapp01' };
    expect(run('linux', { ...base, id: 'l1', program: 'sshd', msg: 'Accepted publickey for tusman from 10.30.2.11 port 50222 ssh2' }))
      .toMatchObject({ category: 'authentication', outcome: 'success', actor_user: 'tusman', src_ip: '10.30.2.11', host: 'SRVEHRAPP01' });
    expect(run('linux', { ...base, id: 'l2', program: 'sshd', msg: 'Failed password for invalid user root from 198.51.100.4 port 4000 ssh2' }))
      .toMatchObject({ outcome: 'failure', actor_user: 'root', severity: 1 });
    expect(run('linux', { ...base, id: 'l3', program: 'sudo', msg: 'tusman : TTY=pts/0 ; PWD=/home/tusman ; USER=root ; COMMAND=/usr/bin/systemctl status ehr' }))
      .toMatchObject({ category: 'privilege', action: 'sudo_command', actor_user: 'tusman' });
    expect(run('linux', { ...base, id: 'l4', program: 'cron', msg: '(svcbackup) CMD (/opt/backup/run.sh)' }))
      .toMatchObject({ category: 'process', action: 'scheduled_job', actor_user: 'svcbackup' });
    expect(run('linux', { ...base, id: 'l5', program: 'kernel', msg: 'something else' }))
      .toMatchObject({ category: 'linux', action: 'kernel_message' });
  });

  it('reads AuditEvents the way real FHIR servers write them', () => {
    const ev = run('ehr', {
      resourceType: 'AuditEvent', id: 'fhir7-abc', recorded: '2026-10-09T10:00:00Z', action: 'R', outcome: '0',
      agent: [
        { who: { reference: 'Device/ehr-app' }, requestor: false },
        { who: { reference: 'Practitioner/88', display: 'Dr Bello' }, requestor: true, network: { address: '10.10.1.21' } },
      ],
      entity: [
        { what: { reference: 'https://ehr.hospital.local/fhir/Patient/P100231/_history/3' } },
        { what: { reference: 'https://ehr.hospital.local/fhir/Observation/obs-9' } },
      ],
    });
    expect(ev).toMatchObject({ actor_user: 'practitioner/88', patient_ref: 'P100231', src_ip: '10.10.1.21', action: 'record_read' });
    expect(ev.attributes).toMatchObject({ resource_type: 'Observation' });
    const r5 = run('ehr', { resourceType: 'AuditEvent', id: 'r5-1', recorded: '2026-10-09T10:00:00Z', action: 'R', patient: { reference: 'Patient/P7' },
      agent: [{ who: { identifier: { value: 'f.bello' } } }] });
    expect(r5).toMatchObject({ actor_user: 'f.bello', patient_ref: 'P7' });
  });

  it('maps a FHIR AuditEvent and finds the patient', () => {
    const e = run('ehr', {
      resourceType: 'AuditEvent', id: 'a1', action: 'R', recorded: '2026-10-09T11:00:00Z', outcome: '0',
      subtype: [{ code: 'read' }],
      agent: [{ who: { identifier: { value: 'GChen' } }, role: [{ coding: [{ code: 'nurse' }] }], network: { address: '10.20.2.12' } }],
      source: { observer: { display: 'SRVEHRAPP01' } },
      entity: [{ what: { reference: 'Patient/p123' } }, { what: { reference: 'Observation/o9' } }, { what: { reference: 'Encounter/e7' } }],
    });
    expect(e).toMatchObject({ category: 'record_access', action: 'record_read', outcome: 'success', actor_user: 'gchen', patient_ref: 'p123', src_ip: '10.20.2.12' });
    expect(e.attributes).toMatchObject({ actor_role: 'nurse', resource_type: 'Observation', encounter_ref: 'e7' });
  });

  it('rejects an EHR record that is not an AuditEvent', () => {
    expect(() => run('ehr', { resourceType: 'Patient', id: 'x' })).toThrow(NormalizeError);
  });

  it('maps a medical device flow with epoch seconds', () => {
    const e = run('medical_device', { flow_id: 'd1', start: 1791460800.5, device: 'pump0003', src_ip: '10.40.1.13', dst_ip: '10.10.1.31', dst_port: 8883, protocol: 'MQTT', packets: 12, bytes: 1800, rate_pps: 6.5, flags: { syn: 1, rst: 0 } });
    expect(e).toMatchObject({ category: 'device_flow', host: 'PUMP0003', dst_port: 8883, protocol: 'mqtt', bytes_out: 1800 });
  });

  it('maps DNS, email and cloud records', () => {
    expect(run('dns', { id: 'q1', ts: '2026-10-09T11:00:00Z', client_ip: '10.20.1.11', qname: 'WWW.News.Example.', qtype: 'a', rcode: 'nxdomain' }))
      .toMatchObject({ category: 'dns', outcome: 'failure', attributes: { query_name: 'www.news.example', registered_domain: 'news.example', response_code: 'NXDOMAIN' } });
    expect(run('email', { message_id: 'm1', received: '2026-10-09T11:00:00Z', sender: 'x@bad.example', recipient: 'GChen@riverbend.example', verdict: 'phish', action: 'delivered', attachments: [{ ext: 'ZIP' }], urls: 3 }))
      .toMatchObject({ action: 'email_delivered', severity: 3, actor_user: 'gchen', attributes: { sender_domain: 'bad.example', attachment_extensions: ['zip'] } });
    expect(run('email', { message_id: 'm2', received: '2026-10-09T11:00:00Z', sender: 'x@bad.example', recipient: 'gchen@riverbend.example', verdict: 'phish', action: 'quarantined' }))
      .toMatchObject({ severity: 2, outcome: 'failure' });
    expect(run('cloud', { eventID: 'c1', eventTime: '2026-10-09T11:00:00Z', eventSource: 'storage', eventName: 'GetObject', userIdentity: { userName: 'gchen' }, sourceIPAddress: '203.0.113.10', requestParameters: { bucketName: 'rbgimaging', key: 'a.dcm' }, additionalEventData: { bytesTransferredOut: 5000 } }))
      .toMatchObject({ category: 'cloud_api', action: 'get_object', bytes_out: 5000, actor_user: 'gchen' });
  });

  it('rejects unusable records with a clear reason', () => {
    const reason = (source: unknown, payload: unknown) => {
      try {
        normalize(source, payload, NOW);
      } catch (err) {
        return (err as Error).message;
      }
      return 'accepted';
    };
    expect(reason('printer', {})).toBe('unknown_source');
    expect(reason('constructor', {})).toBe('unknown_source');
    expect(reason('__proto__', {})).toBe('unknown_source');
    expect(reason(42, {})).toBe('unknown_source');
    expect(reason('dns', 'text')).toBe('payload_not_an_object');
    expect(reason('dns', [1])).toBe('payload_not_an_object');
    expect(reason('dns', { ts: '2026-10-09T11:00:00Z' })).toBe('missing_event_id');
    expect(reason('dns', { id: 'q', ts: 'yesterday' })).toBe('missing_or_bad_time');
    expect(reason('dns', { id: 'q', ts: '2026-10-09T13:00:00Z' })).toBe('time_in_future');
    expect(reason('dns', { id: 'x'.repeat(201), ts: '2026-10-09T11:00:00Z' })).toBe('event_id_too_long');
  });

  it('drops bad addresses and ports without rejecting the record', () => {
    const e = run('firewall', { id: 'f2', ts: '2026-10-09T11:00:00Z', action: 'allow', src: 'not an ip', dst: '10.10.1.10', dpt: 99999 });
    expect(e.src_ip).toBeNull();
    expect(e.dst_port).toBeNull();
    expect(e.dst_ip).toBe('10.10.1.10');
  });
});
