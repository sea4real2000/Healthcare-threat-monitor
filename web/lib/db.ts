import postgres from 'postgres';

type Sql = ReturnType<typeof postgres>;
const holder = globalThis as unknown as { __htmSql?: Sql };

function sslMode(url: string): 'require' | false {
  const forced = process.env.DATABASE_SSL;
  if (forced === 'disable') return false;
  if (forced === 'require') return 'require';
  // Local databases have no certificate. Everything else must use TLS.
  return /@(localhost|127\.0\.0\.1|\[::1\])[:/]/.test(url) ? false : 'require';
}

/** One shared server side connection pool. Never import this from a client component. */
export function db(): Sql {
  if (!holder.__htmSql) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error('DATABASE_URL is not set');
    holder.__htmSql = postgres(url, {
      // Supabase transaction pooling does not support prepared statements.
      prepare: false,
      max: Number(process.env.DATABASE_POOL_MAX ?? 5),
      idle_timeout: 20,
      connect_timeout: 10,
      ssl: sslMode(url),
      onnotice: () => {},
    });
  }
  return holder.__htmSql;
}
