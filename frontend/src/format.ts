export function timeAgo(iso: string | null): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  const secs = Math.max(1, Math.round((Date.now() - then) / 1000));
  const units: [number, string][] = [
    [60, "s"],
    [60, "m"],
    [24, "h"],
    [30, "d"],
    [12, "mo"],
    [Number.POSITIVE_INFINITY, "y"],
  ];
  let value = secs;
  for (const [span, suffix] of units) {
    if (value < span) return `${value}${suffix} ago`;
    value = Math.floor(value / span);
  }
  return "long ago";
}

export function risk(score: number): string {
  return score.toFixed(2);
}

export function shortSha(sha: string): string {
  return sha.length > 7 ? sha.slice(0, 7) : sha;
}
