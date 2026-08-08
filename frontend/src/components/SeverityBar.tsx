import type { Severity } from "../types";

const ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

// Part-to-whole of a scan's open findings by severity — a stacked mini-bar so
// the critical/high mix reads at a glance in a table row (dataviz: stacked bar).
export function SeverityBar({
  counts,
  total,
}: {
  counts: Partial<Record<Severity, number>>;
  total: number;
}) {
  if (total === 0) {
    return <span className="dim small">—</span>;
  }
  return (
    <div className="sevbar">
      <span className="track">
        {ORDER.map((sev) => {
          const n = counts[sev] ?? 0;
          if (n === 0) return null;
          return (
            <span
              key={sev}
              className={`seg ${sev}`}
              style={{ width: `${(n / total) * 100}%` }}
              title={`${n} ${sev.toLowerCase()}`}
            />
          );
        })}
      </span>
      <span className="count">{total}</span>
    </div>
  );
}
