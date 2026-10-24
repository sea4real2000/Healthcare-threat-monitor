'use client';

import { useState } from 'react';

export interface RatePoint {
  time: string;
  value: number;
}

interface Props {
  points: RatePoint[];
  ariaLabel: string;
  tipTemplate: string;
  tableLabel: string;
  minuteHeading: string;
  eventsHeading: string;
}

const W = 960;
const H = 220;
const PAD = { top: 12, right: 12, bottom: 26, left: 44 };

function niceCeil(n: number): number {
  if (n <= 4) return 4;
  const pow = 10 ** Math.floor(Math.log10(n));
  for (const m of [1, 2, 4, 5, 10]) if (m * pow >= n) return m * pow;
  return 10 * pow;
}

const fmt = new Intl.NumberFormat('en-US');

/** Events per minute across all sources: one series, one axis, hover for the exact value. */
export function RateChart({ points, ariaLabel, tipTemplate, tableLabel, minuteHeading, eventsHeading }: Props) {
  const [active, setActive] = useState<number | null>(null);
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;
  const top = niceCeil(Math.max(...points.map((p) => p.value), 0));
  const step = plotW / Math.max(points.length, 1);
  const barW = Math.max(step - 2, 1);
  const y = (v: number) => PAD.top + plotH - (v / top) * plotH;
  const ticks = [0, top / 2, top];
  const labelEvery = Math.max(Math.round(points.length / 6), 1);

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    const box = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - box.left) / box.width) * W - PAD.left;
    const i = Math.floor(x / step);
    setActive(i >= 0 && i < points.length ? i : null);
  }

  const tip = active !== null ? points[active] : null;
  return (
    <div className="chart">
      <div className="chart-inner">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={ariaLabel} onMouseMove={onMove} onMouseLeave={() => setActive(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line className={t === 0 ? 'axis' : 'grid'} x1={PAD.left} x2={W - PAD.right} y1={y(t)} y2={y(t)} />
            <text x={PAD.left - 8} y={y(t) + 4} textAnchor="end">
              {fmt.format(t)}
            </text>
          </g>
        ))}
        {points.map((p, i) => {
          const h = p.value === 0 ? 0 : Math.max(y(0) - y(p.value), 1.5);
          return (
            <rect
              key={p.time}
              className={active === null || active === i ? 'bar' : 'bar bar-dim'}
              x={PAD.left + i * step + 1}
              y={y(0) - h}
              width={barW}
              height={h}
              rx="2"
            />
          );
        })}
        {points.map((p, i) =>
          i % labelEvery === 0 ? (
            <text key={p.time} x={PAD.left + i * step + step / 2} y={H - 8} textAnchor="middle">
              {p.time}
            </text>
          ) : null,
        )}
      </svg>
      {tip && active !== null && (
        <div className="chart-tip num" style={{ left: `${((PAD.left + active * step + step / 2) / W) * 100}%` }}>
          {tipTemplate.replace('{time}', tip.time).replace('{events}', fmt.format(tip.value))}
        </div>
      )}
      </div>
      <details className="as-table">
        <summary>{tableLabel}</summary>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{minuteHeading}</th>
                <th className="right">{eventsHeading}</th>
              </tr>
            </thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.time}>
                  <td className="num">{p.time}</td>
                  <td className="right num">{fmt.format(p.value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
