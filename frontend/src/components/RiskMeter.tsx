// The composite risk score is ChainSentry's differentiator — show it, don't
// just print it. Bands mirror the default policy thresholds (fail ≥ 0.75,
// warn ≥ 0.50) so the bar's color reads the same way the gate does.
function band(score: number): "crit" | "high" | "med" | "low" {
  if (score >= 0.75) return "crit";
  if (score >= 0.5) return "high";
  if (score >= 0.25) return "med";
  return "low";
}

export function RiskMeter({ score }: { score: number }) {
  const pct = Math.round(Math.max(0, Math.min(1, score)) * 100);
  return (
    <div className="risk" title={`Composite risk ${score.toFixed(4)} of 1`}>
      <span className="track">
        <span className={`fill ${band(score)}`} style={{ width: `${pct}%` }} />
      </span>
      <span className="score">{score.toFixed(2)}</span>
    </div>
  );
}
