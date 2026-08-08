import type { ReactNode } from "react";

export function StatTile({
  label,
  value,
  tone,
  foot,
  icon,
}: {
  label: string;
  value: number | string;
  tone?: "critical" | "kev";
  foot?: string;
  icon?: ReactNode;
}) {
  return (
    <div className={`card tile ${tone ?? ""}`}>
      <div className="label">
        {icon}
        {label}
      </div>
      <div className="value">{value}</div>
      {foot && <div className="foot">{foot}</div>}
    </div>
  );
}
