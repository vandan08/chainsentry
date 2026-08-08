import type { GateStatus } from "../types";

const LOOK: Record<GateStatus, { cls: string; icon: string }> = {
  PASS: { cls: "pass", icon: "✓" },
  WARN: { cls: "warn", icon: "!" },
  FAIL: { cls: "fail", icon: "✕" },
};

export function GateBadge({ gate }: { gate: GateStatus | null }) {
  if (!gate) {
    return <span className="badge none">— no scan</span>;
  }
  const { cls, icon } = LOOK[gate];
  return (
    <span className={`badge ${cls}`}>
      {icon} {gate}
    </span>
  );
}
