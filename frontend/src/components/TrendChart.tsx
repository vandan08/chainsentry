import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { TrendPoint } from "../types";

// Findings-over-time is a continuous magnitude across ordered scans → lines.
// Total uses the neutral series hue; criticals/highs use the fixed status
// palette so they read as severity, never as an arbitrary category.
const SERIES = [
  { key: "totalFindings", label: "Total", color: "var(--series-1)" },
  { key: "highs", label: "High", color: "var(--status-serious)" },
  { key: "criticals", label: "Critical", color: "var(--status-critical)" },
] as const;

function shortSha(sha: string) {
  return sha.length > 7 ? sha.slice(0, 7) : sha;
}

export function TrendChart({ points }: { points: TrendPoint[] }) {
  if (points.length === 0) {
    return <div className="state">No completed scans yet — trend appears after the first scan.</div>;
  }
  const data = points.map((p) => ({ ...p, sha: shortSha(p.commitSha) }));

  return (
    <div>
      <div className="legend">
        {SERIES.map((s) => (
          <span key={s.key} className="item">
            <span className="swatch" style={{ background: s.color }} />
            {s.label}
          </span>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={240}>
        <LineChart data={data} margin={{ top: 8, right: 16, bottom: 4, left: -12 }}>
          <CartesianGrid stroke="var(--gridline)" vertical={false} />
          <XAxis
            dataKey="sha"
            tick={{ fill: "var(--muted)", fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: "var(--baseline)" }}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: "var(--muted)", fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={40}
          />
          <Tooltip
            contentStyle={{
              background: "var(--surface-1)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              fontSize: 12,
              color: "var(--text-primary)",
            }}
            labelStyle={{ color: "var(--text-secondary)" }}
          />
          {SERIES.map((s) => (
            <Line
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.label}
              stroke={s.color}
              strokeWidth={2}
              dot={{ r: 2.5, fill: s.color }}
              activeDot={{ r: 4 }}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
