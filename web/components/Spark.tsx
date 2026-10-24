/** A strip of one bar per minute for a single source, scaled to its own peak. */
export function Spark({ values, label }: { values: number[]; label: string }) {
  const width = 240;
  const height = 28;
  const step = width / Math.max(values.length, 1);
  const barWidth = Math.max(step - 1, 1);
  const peak = Math.max(...values, 0);
  return (
    <svg className="spark" width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
      <rect className="spark-base" x="0" y={height - 1} width={width} height="1" />
      {peak > 0 &&
        values.map((v, i) => {
          if (v === 0) return null;
          const h = Math.max((v / peak) * (height - 3), 1.5);
          return <rect key={i} x={i * step} y={height - 1 - h} width={barWidth} height={h} rx="1" />;
        })}
    </svg>
  );
}
