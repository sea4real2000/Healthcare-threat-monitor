import { arr, int, ip, obj, str, type Normalizer, type Outcome } from './helpers';

// One mapper per log source. Each takes the record as the source system writes it
// and returns the fields of the common schema. Anything source specific that the
// common columns cannot hold goes into attributes.

const firewall: Normalizer = (r) => {
  const action = str(r.action)?.toLowerCase() ?? 'unknown';
  return {
    source_event_id: r.id,
    occurred_at: r.ts,
    category: 'network_flow',
    action: action === 'allow' ? 'flow_allowed' : action === 'deny' ? 'flow_denied' : 'flow_unknown',
    outcome: action === 'allow' ? 'success' : action === 'deny' ? 'failure' : 'unknown',
    severity: action === 'deny' ? 1 : 0,
    src_ip: ip(r.src),
    dst_ip: ip(r.dst),
    dst_port: int(r.dpt),
    protocol: str(r.proto),
    bytes_out: int(r.sent),
    bytes_in: int(r.rcvd),
    attributes: {
      firewall: str(r.fw),
      src_port: int(r.spt),
      src_zone: str(r.src_zone),
      dst_zone: str(r.dst_zone),
      rule: str(r.rule),
    },
  };
};

const vpn: Normalizer = (r) => {
  const event = str(r.event)?.toLowerCase() ?? 'unknown';
  const failed = event === 'auth_failed';
  return {
    source_event_id: r.id,
    occurred_at: r.time,
    category: 'session',
    action: `vpn_${event}`,
    outcome: failed ? 'failure' : 'success',
    severity: failed ? 1 : 0,
    actor_user: str(r.user),
    src_ip: ip(r.client_ip),
    bytes_out: int(r.bytes_out),
    bytes_in: int(r.bytes_in),
    attributes: {
      gateway: str(r.gateway),
      assigned_ip: ip(r.assigned_ip),
      country: str(r.country),
      device_id: str(r.device_id),
      duration_seconds: int(r.duration_s),
    },
  };
};

const EDR_CATEGORY: Record<string, string> = {
  process_start: 'process',
  file_write: 'file',
  file_rename: 'file',
  file_delete: 'file',
  registry_set: 'registry',
  network_connect: 'network_flow',
};

const edr: Normalizer = (r) => {
  const type = str(r.event_type)?.toLowerCase() ?? 'unknown';
  const process = obj(r.process);
  const file = obj(r.file);
  const net = obj(r.network);
  return {
    source_event_id: r.event_id,
    occurred_at: r.timestamp,
    category: EDR_CATEGORY[type] ?? 'endpoint',
    action: type,
    outcome: 'success',
    severity: 0,
    actor_user: str(r.user),
    host: str(r.hostname),
    dst_ip: ip(net.dst_ip),
    dst_port: int(net.dst_port),
    protocol: str(net.protocol),
    attributes: {
      process_name: str(process.name)?.toLowerCase(),
      process_id: int(process.pid),
      parent_name: str(process.parent)?.toLowerCase(),
      command_line: str(process.cmdline),
      file_path: str(file.path),
      file_extension: str(file.ext)?.toLowerCase(),
      file_new_path: str(file.new_path),
      registry_key: str(obj(r.registry).key),
      sensor_version: str(r.sensor_version),
    },
  };
};

// Windows event identifiers the platform understands. Others are kept as generic events.
const WINDOWS_EVENTS: Record<number, { category: string; action: string; outcome: Outcome; severity: 0 | 1 | 2 | 3 }> = {
  4624: { category: 'authentication', action: 'logon', outcome: 'success', severity: 0 },
  4625: { category: 'authentication', action: 'logon', outcome: 'failure', severity: 1 },
  4634: { category: 'authentication', action: 'logoff', outcome: 'success', severity: 0 },
  4672: { category: 'privilege', action: 'special_privileges_assigned', outcome: 'success', severity: 1 },
  4688: { category: 'process', action: 'process_start', outcome: 'success', severity: 0 },
  4698: { category: 'persistence', action: 'scheduled_task_created', outcome: 'success', severity: 1 },
  4720: { category: 'account', action: 'account_created', outcome: 'success', severity: 1 },
  4732: { category: 'account', action: 'group_member_added', outcome: 'success', severity: 1 },
  4740: { category: 'authentication', action: 'account_locked_out', outcome: 'failure', severity: 1 },
  1102: { category: 'defense_evasion', action: 'audit_log_cleared', outcome: 'success', severity: 3 },
  7036: { category: 'service', action: 'service_state_changed', outcome: 'success', severity: 0 },
  7045: { category: 'service', action: 'service_installed', outcome: 'success', severity: 1 },
};

/** The last part of a Windows path, in lower case: C:\\Windows\\System32\\cmd.exe becomes cmd.exe. */
function baseName(path: string | null): string | null {
  if (!path) return null;
  const name = path.split(/[\\/]/).pop() ?? '';
  return name ? name.toLowerCase() : null;
}

// Values Windows writes when a field does not apply.
const NO_VALUE = new Set(['-', '', '%%1793']);

// In these events the target is the account or group acted on, so the person who acted comes first.
const SUBJECT_FIRST = new Set([4720, 4732]);

function windowsUser(eventId: number, data: Record<string, unknown>): string | null {
  const keys = SUBJECT_FIRST.has(eventId) ? ['SubjectUserName', 'TargetUserName'] : ['TargetUserName', 'SubjectUserName'];
  for (const key of keys) {
    const v = str(data[key]);
    // Machine accounts end in a dollar sign and are not people.
    if (v && !NO_VALUE.has(v) && !v.endsWith('$')) return v;
  }
  return null;
}

const windows: Normalizer = (r) => {
  const eventId = int(r.EventID) ?? 0;
  const known = WINDOWS_EVENTS[eventId];
  const data = obj(r.Data);
  // Service changes name their service and state param1 and param2 in the System log.
  const serviceName = str(data.ServiceName) ?? (eventId === 7036 ? str(data.param1) : null);
  const serviceState = str(data.State) ?? (eventId === 7036 ? str(data.param2)?.toLowerCase() : null);
  // A fully qualified computer name is kept to its first part, the way the inventory names machines.
  const computer = str(r.Computer)?.split('.')[0] ?? null;
  return {
    source_event_id: str(r.RecordId) ? `${computer ?? 'unknown'}:${str(r.Channel) === 'System' ? 'sys:' : ''}${str(r.RecordId)}` : null,
    occurred_at: r.TimeCreated,
    category: known?.category ?? 'windows',
    action: known?.action ?? `event_${eventId}`,
    outcome: known?.outcome ?? 'unknown',
    severity: known?.severity ?? 0,
    actor_user: windowsUser(eventId, data),
    host: computer,
    src_ip: ip(data.IpAddress),
    attributes: {
      event_id: eventId,
      channel: str(r.Channel),
      logon_type: int(data.LogonType),
      failure_reason: str(data.FailureReason),
      service_name: serviceName,
      service_state: serviceState,
      privileges: str(data.PrivilegeList),
      process_name: baseName(str(data.NewProcessName)),
      parent_name: baseName(str(data.ParentProcessName)),
      command_line: str(data.CommandLine),
      task_name: str(data.TaskName),
      group_name: eventId === 4732 ? str(data.TargetUserName) : null,
      member: str(data.MemberName),
      workstation: str(data.WorkstationName),
    },
  };
};

// Linux arrives as syslog text, so the message is parsed here.
const SSH_RESULT = /^(Accepted|Failed) (\w+) for (?:invalid user )?(\S+) from (\S+) port (\d+)/;
const SUDO = /^\s*(\S+) : .*USER=(\S+) ; COMMAND=(.+)$/;
const CRON = /^\((\S+)\) CMD \((.+)\)$/;

const linux: Normalizer = (r) => {
  const program = str(r.program)?.toLowerCase() ?? 'unknown';
  const msg = str(r.msg) ?? '';
  const base = {
    source_event_id: r.id,
    occurred_at: r.ts,
    host: str(r.host),
  };
  const ssh = program === 'sshd' ? SSH_RESULT.exec(msg) : null;
  if (ssh) {
    const ok = ssh[1] === 'Accepted';
    return {
      ...base,
      category: 'authentication',
      action: 'logon',
      outcome: ok ? 'success' : 'failure',
      severity: ok ? 0 : 1,
      actor_user: ssh[3],
      src_ip: ip(ssh[4]),
      protocol: 'ssh',
      attributes: { program, method: ssh[2], src_port: int(ssh[5]) },
    };
  }
  const sudo = program === 'sudo' ? SUDO.exec(msg) : null;
  if (sudo) {
    return {
      ...base,
      category: 'privilege',
      action: 'sudo_command',
      outcome: 'success',
      severity: 1,
      actor_user: sudo[1],
      attributes: { program, run_as: sudo[2], command_line: sudo[3] },
    };
  }
  const cron = program === 'cron' ? CRON.exec(msg) : null;
  if (cron) {
    return {
      ...base,
      category: 'process',
      action: 'scheduled_job',
      outcome: 'success',
      severity: 0,
      actor_user: cron[1],
      attributes: { program, command_line: cron[2] },
    };
  }
  return {
    ...base,
    category: 'linux',
    action: `${program}_message`,
    outcome: 'unknown',
    severity: 0,
    attributes: { program, facility: str(r.facility), message: msg.slice(0, 400) },
  };
};

const FHIR_ACTION: Record<string, string> = { C: 'create', R: 'read', U: 'update', D: 'delete', E: 'execute' };

/** The ID in a reference such as Patient/123, or https://server/fhir/Patient/123/_history/2. */
function idFromReference(ref: string | null, type: string): string | null {
  if (!ref) return null;
  const at = ref.startsWith(`${type}/`) ? 0 : ref.indexOf(`/${type}/`) + 1;
  if (at < 0 || (at === 0 && !ref.startsWith(`${type}/`))) return null;
  const id = ref.slice(at + type.length + 1).split('/')[0];
  return id || null;
}

function referenceId(entities: unknown[], type: string): string | null {
  for (const e of entities) {
    const id = idFromReference(str(obj(obj(e).what).reference), type);
    if (id) return id;
  }
  return null;
}

/** EHR access records arrive as FHIR R4 AuditEvent resources. */
const ehr: Normalizer = (r) => {
  if (r.resourceType !== 'AuditEvent') {
    return { source_event_id: null, occurred_at: null, category: 'record_access', action: 'unknown' };
  }
  // The person who asked is the agent marked as requestor. Without that mark, the first agent.
  const agents = arr(r.agent).map((a) => obj(a));
  const agent = agents.find((a) => a.requestor === true) ?? agents[0] ?? {};
  const who = obj(agent.who);
  const entities = arr(r.entity);
  const code = str(r.action)?.toUpperCase() ?? '';
  const outcomeCode = str(r.outcome) ?? '';
  const resourceRef = entities
    .map((e) => str(obj(obj(e).what).reference))
    .find((ref) => ref && !idFromReference(ref, 'Patient') && !idFromReference(ref, 'Encounter'));
  return {
    source_event_id: r.id,
    occurred_at: r.recorded,
    category: 'record_access',
    action: `record_${FHIR_ACTION[code] ?? 'access'}`,
    outcome: outcomeCode === '0' ? 'success' : outcomeCode === '' ? 'unknown' : 'failure',
    severity: outcomeCode === '0' || outcomeCode === '' ? 0 : 1,
    // A login name is best. Servers that give none name the person by reference or display name instead.
    actor_user: str(obj(who.identifier).value) ?? str(agent.altId) ?? str(who.reference) ?? str(who.display) ?? str(agent.name),
    src_ip: ip(obj(agent.network).address),
    // FHIR R5 names the patient directly. R4 lists the patient among the entities.
    patient_ref: idFromReference(str(obj(r.patient).reference), 'Patient') ?? referenceId(entities, 'Patient'),
    attributes: {
      actor_role: str(obj(arr(obj(arr(agent.role)[0]).coding)[0]).code),
      resource_type: resourceRef ? (/(?:^|\/)([A-Z][A-Za-z]+)\/[^/]+(?:\/_history\/[^/]+)?$/.exec(resourceRef)?.[1] ?? 'Other') : 'Patient',
      resource_ref: resourceRef,
      encounter_ref: referenceId(entities, 'Encounter'),
      interaction: str(obj(arr(r.subtype)[0]).code),
      observer: str(obj(obj(r.source).observer).display),
      purpose: str(obj(arr(obj(arr(r.purposeOfEvent)[0]).coding)[0]).code),
    },
  };
};

const medical_device: Normalizer = (r) => {
  const flags = obj(r.flags);
  return {
    source_event_id: r.flow_id,
    occurred_at: r.start,
    category: 'device_flow',
    action: 'device_flow',
    outcome: 'success',
    severity: 0,
    host: str(r.device),
    src_ip: ip(r.src_ip),
    dst_ip: ip(r.dst_ip),
    dst_port: int(r.dst_port),
    protocol: str(r.protocol),
    bytes_out: int(r.bytes),
    attributes: {
      packets: int(r.packets),
      rate_pps: typeof r.rate_pps === 'number' ? r.rate_pps : null,
      duration_seconds: typeof r.duration_s === 'number' ? r.duration_s : null,
      syn_count: int(flags.syn),
      rst_count: int(flags.rst),
      device_type: str(r.device_type),
    },
  };
};

const dns: Normalizer = (r) => {
  const rcode = str(r.rcode)?.toUpperCase() ?? 'UNKNOWN';
  const qname = str(r.qname)?.toLowerCase().replace(/\.$/, '') ?? null;
  return {
    source_event_id: r.id,
    occurred_at: r.ts,
    category: 'dns',
    action: 'dns_query',
    outcome: rcode === 'NOERROR' ? 'success' : 'failure',
    severity: 0,
    src_ip: ip(r.client_ip),
    protocol: 'dns',
    attributes: {
      query_name: qname,
      query_type: str(r.qtype)?.toUpperCase(),
      response_code: rcode,
      resolver: str(r.resolver),
      answer: ip(r.answer),
      registered_domain: qname ? qname.split('.').slice(-2).join('.') : null,
    },
  };
};

const email: Normalizer = (r) => {
  const verdict = str(r.verdict)?.toLowerCase() ?? 'unknown';
  const action = str(r.action)?.toLowerCase() ?? 'unknown';
  const attachments = arr(r.attachments).map((a) => obj(a));
  const bad = verdict === 'phish' || verdict === 'malware';
  const recipient = str(r.recipient)?.toLowerCase() ?? null;
  return {
    source_event_id: r.message_id,
    occurred_at: r.received,
    category: 'email',
    action: `email_${action}`,
    outcome: action === 'delivered' ? 'success' : action === 'unknown' ? 'unknown' : 'failure',
    // A bad message that still reached the inbox matters more than one that was stopped.
    severity: bad ? (action === 'delivered' ? 3 : 2) : verdict === 'spam' ? 1 : 0,
    actor_user: recipient ? recipient.split('@')[0] : null,
    attributes: {
      sender: str(r.sender)?.toLowerCase(),
      sender_domain: str(r.sender)?.toLowerCase().split('@')[1],
      recipient,
      verdict,
      url_count: int(r.urls),
      attachment_count: attachments.length,
      attachment_extensions: attachments.map((a) => str(a.ext)?.toLowerCase()).filter(Boolean),
      spf: str(r.spf),
      dkim: str(r.dkim),
      subject_hash: str(r.subject_hash),
    },
  };
};

const cloud: Normalizer = (r) => {
  const params = obj(r.requestParameters);
  const extra = obj(r.additionalEventData);
  const error = str(r.errorCode);
  const name = str(r.eventName) ?? 'Unknown';
  const sensitive = /Policy|CreateUser|CreateAccessKey|DeleteBucket|PutBucketAcl/.test(name);
  return {
    source_event_id: r.eventID,
    occurred_at: r.eventTime,
    category: 'cloud_api',
    action: name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase(),
    outcome: error ? 'failure' : 'success',
    severity: error || sensitive ? 1 : 0,
    actor_user: str(obj(r.userIdentity).userName),
    src_ip: ip(r.sourceIPAddress),
    bytes_out: int(extra.bytesTransferredOut),
    bytes_in: int(extra.bytesTransferredIn),
    attributes: {
      service: str(r.eventSource),
      bucket: str(params.bucketName),
      object_key: str(params.key),
      error_code: error,
      region: str(r.awsRegion),
      user_agent: str(r.userAgent),
    },
  };
};

export const NORMALIZERS: Record<string, Normalizer> = {
  firewall,
  vpn,
  edr,
  windows,
  linux,
  ehr,
  medical_device,
  dns,
  email,
  cloud,
};
