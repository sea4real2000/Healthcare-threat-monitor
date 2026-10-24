import { db } from './db';

export interface SourceRow {
  id: string;
  label: string;
  description: string | null;
  events: number;
  last_at: Date | null;
  buckets: number[];
}

export interface RecentEvent {
  id: string;
  occurred_at: Date;
  source_label: string;
  action: string;
  outcome: string;
  actor_user: string | null;
  host: string | null;
  severity: number;
}

export interface Overview {
  now: Date;
  windowStart: Date;
  windowMinutes: number;
  sources: SourceRow[];
  totals: number[];
  totalEvents: number;
  reporting: number;
  assetsTotal: number;
  assetsSeen: number;
  rejects: number;
  recent: RecentEvent[];
}

export async function loadOverview(windowMinutes: number, silentAfterMinutes: number, recentLimit: number): Promise<Overview> {
  const sql = db();
  const [clock] = await sql<{ now: Date; window_start: Date }[]>`
    select now() as now,
           date_trunc('minute', now()) - make_interval(mins => ${windowMinutes - 1}::int) as window_start`;
  const start = clock.window_start;

  const [sources, buckets, [assets], [rejects], recent] = await Promise.all([
    sql<{ id: string; label: string; description: string | null; last_at: Date | null }[]>`
      select s.id, s.label, s.description,
             (select e.occurred_at from events e where e.source = s.id order by e.occurred_at desc limit 1) as last_at
      from sources s where s.enabled order by s.sort_order, s.id`,
    sql<{ source: string; bucket: number; n: number }[]>`
      select source, floor(extract(epoch from (occurred_at - ${start}::timestamptz)) / 60)::int as bucket, count(*)::int as n
      from events
      where occurred_at >= ${start}::timestamptz and occurred_at <= ${clock.now}::timestamptz
      group by 1, 2`,
    sql<{ total: number; seen: number }[]>`
      select count(*)::int as total,
             count(*) filter (where last_seen_at >= ${start}::timestamptz)::int as seen
      from assets`,
    sql<{ n: number }[]>`
      select count(*)::int as n from ingest_rejects where received_at >= ${start}::timestamptz`,
    sql<RecentEvent[]>`
      select e.id::text as id, e.occurred_at, s.label as source_label, e.action, e.outcome, e.actor_user, e.host, e.severity
      from events e join sources s on s.id = e.source
      where e.occurred_at <= ${clock.now}::timestamptz
      order by e.occurred_at desc, e.id desc limit ${recentLimit}::int`,
  ]);

  const bySource = new Map<string, number[]>();
  const totals = new Array<number>(windowMinutes).fill(0);
  for (const b of buckets) {
    if (b.bucket < 0 || b.bucket >= windowMinutes) continue;
    let list = bySource.get(b.source);
    if (!list) {
      list = new Array<number>(windowMinutes).fill(0);
      bySource.set(b.source, list);
    }
    list[b.bucket] = b.n;
    totals[b.bucket] += b.n;
  }

  const silentBefore = clock.now.getTime() - silentAfterMinutes * 60000;
  const rows: SourceRow[] = sources.map((s) => {
    const list = bySource.get(s.id) ?? new Array<number>(windowMinutes).fill(0);
    return { ...s, buckets: list, events: list.reduce((a, b) => a + b, 0) };
  });

  return {
    now: clock.now,
    windowStart: start,
    windowMinutes,
    sources: rows,
    totals,
    totalEvents: totals.reduce((a, b) => a + b, 0),
    reporting: rows.filter((r) => r.last_at && r.last_at.getTime() >= silentBefore).length,
    assetsTotal: assets.total,
    assetsSeen: assets.seen,
    rejects: rejects.n,
    recent,
  };
}

export interface AssetRow {
  id: string;
  kind: string;
  role: string;
  os: string | null;
  ip: string | null;
  department: string | null;
  zone: string;
  status: string;
  last_seen_at: Date | null;
  events: number;
}

export interface AssetFilters {
  q: string;
  kind: string;
  status: string;
  department: string;
}

export async function loadAssets(filters: AssetFilters, windowMinutes: number, limit: number) {
  const sql = db();
  const like = `%${filters.q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
  const [[clock], [counts], departments, rows] = await Promise.all([
    sql<{ now: Date }[]>`select now() as now`,
    sql<{ total: number; workstation: number; server: number; medical_device: number; network: number; isolated: number }[]>`
      select count(*)::int as total,
             count(*) filter (where kind = 'workstation')::int as workstation,
             count(*) filter (where kind = 'server')::int as server,
             count(*) filter (where kind = 'medical_device')::int as medical_device,
             count(*) filter (where kind = 'network')::int as network,
             count(*) filter (where status = 'isolated')::int as isolated
      from assets`,
    sql<{ id: string; name: string }[]>`select id, name from departments order by name`,
    sql<AssetRow[]>`
      select a.id, a.kind, a.role, a.os, host(a.ip) as ip, d.name as department, a.zone, a.status, a.last_seen_at,
             coalesce(ev.n, 0)::int as events
      from assets a
      left join departments d on d.id = a.department_id
      left join (
        select host, count(*) as n from events
        where occurred_at >= now() - make_interval(mins => ${windowMinutes}::int) and host is not null
        group by host
      ) ev on ev.host = a.id
      where (${filters.q}::text = '' or a.id ilike ${like}::text or host(a.ip) ilike ${like}::text or a.role ilike ${like}::text)
        and (${filters.kind}::text = '' or a.kind = ${filters.kind}::text)
        and (${filters.status}::text = '' or a.status = ${filters.status}::text)
        and (${filters.department}::text = '' or a.department_id = ${filters.department}::text)
      order by a.kind, a.id
      limit ${limit}::int`,
  ]);
  return { now: clock.now, counts, departments, rows };
}
