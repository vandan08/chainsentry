import type { GateStatus } from "../types";

const LOOK: Record<GateStatus, { cls: string; glyph: string; headline: string }> = {
  PASS: { cls: "pass", glyph: "✓", headline: "Gate passed" },
  WARN: { cls: "warn", glyph: "!", headline: "Gate passed with warnings" },
  FAIL: { cls: "fail", glyph: "✕", headline: "Gate failed" },
};

/** The verdict is the headline of a scan — a full-width banner, not a chip. */
export function GateHero({ gate, detail }: { gate: GateStatus | null; detail: string }) {
  if (!gate) {
    return (
      <div className="gate-hero warn">
        <span className="glyph">…</span>
        <div>
          <div className="headline">No verdict</div>
          <div className="detail">This scan has not completed.</div>
        </div>
      </div>
    );
  }
  const { cls, glyph, headline } = LOOK[gate];
  return (
    <div className={`gate-hero ${cls}`}>
      <span className="glyph">{glyph}</span>
      <div>
        <div className="headline">{headline}</div>
        <div className="detail">{detail}</div>
      </div>
    </div>
  );
}
