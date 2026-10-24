import { SettingsTabs } from '@/components/SettingsTabs';
import { Flash } from '@/components/ui';
import { removeImage, saveImage } from '@/lib/actions';
import { db } from '@/lib/db';
import { formatAgo, formatNumber } from '@/lib/format';
import { requireUser } from '@/lib/session';
import { getCopy, numberSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function ImagesPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [t, params, limit] = await Promise.all([getCopy(), searchParams, numberSetting('media.max_bytes')]);
  const slots = await db()<
    { slot: string; has: boolean; sha256: string | null; alt: string; width: number | null; height: number | null; size_bytes: number | null; updated_at: Date; updated_by: string | null; now: Date }[]
  >`select slot, bytes is not null as has, sha256, alt, width, height, size_bytes, updated_at, updated_by, now() as now from site_images order by position, slot`;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('settings.title')}</h1>
          <p className="lede">{t('settings.images.lede')}</p>
        </div>
      </header>
      <SettingsTabs t={t} current="images" admin />
      <Flash params={params} t={t} scope="images" />
      <p className="panel-note image-rules">{t('settings.images.rules', { limit: (limit / 1_000_000).toFixed(limit % 1_000_000 === 0 ? 0 : 1) })}</p>
      {slots.map((s) => (
        <section className="panel" key={s.slot}>
          <div className="panel-head">
            <h2>{t(`settings.images.slot.${s.slot}.title`)}</h2>
            {s.has && (
              <span className="panel-note">
                {formatAgo(s.updated_at, s.now, t)}
                {s.updated_by ? `, ${s.updated_by}` : ''}
              </span>
            )}
          </div>
          <div className="image-slot">
            <div className="image-now">
              {s.has ? (
                <>
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={`/api/media/${s.slot}?v=${s.sha256!.slice(0, 16)}`} alt={s.alt} width={s.width ?? undefined} height={s.height ?? undefined} />
                  <p className="panel-note">
                    {t('settings.images.details', { width: formatNumber(s.width ?? 0), height: formatNumber(s.height ?? 0), size: formatNumber(Math.round((s.size_bytes ?? 0) / 1000)) })}
                  </p>
                </>
              ) : (
                <p className="image-empty">{t('settings.images.none')}</p>
              )}
            </div>
            <div className="image-edit">
              <p>{t(`settings.images.slot.${s.slot}.guide`)}</p>
              <p className="panel-note">
                <strong>{t('settings.images.shape')}:</strong> {t(`settings.images.slot.${s.slot}.shape`)}
              </p>
              <form action={saveImage} className="stack">
                <input type="hidden" name="slot" value={s.slot} />
                <label>
                  {t('settings.images.file')}
                  <input type="file" name="file" accept="image/jpeg,image/png,image/webp" required={!s.has} />
                  {s.has && <span className="sub">{t('settings.images.file_keep')}</span>}
                </label>
                <label>
                  {t('settings.images.alt')}
                  <input name="alt" required maxLength={300} defaultValue={s.alt} />
                  <span className="sub">{t('settings.images.alt_hint')}</span>
                </label>
                <div>
                  <button className="button button-primary" type="submit">
                    {t('settings.images.save')}
                  </button>
                </div>
              </form>
              {s.has && (
                <form action={removeImage}>
                  <input type="hidden" name="slot" value={s.slot} />
                  <button className="button" type="submit">
                    {t('settings.images.remove')}
                  </button>
                </form>
              )}
            </div>
          </div>
        </section>
      ))}
    </>
  );
}
