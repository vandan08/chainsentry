/** Content-shaped loading placeholders — steadier than a spinner while data lands. */
export function TilesSkeleton() {
  return (
    <div className="skel-tiles">
      {[0, 1, 2, 3].map((i) => (
        <div key={i} className="skeleton" style={{ height: 92 }} />
      ))}
    </div>
  );
}

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="card" style={{ display: "grid", gap: 10 }}>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton" style={{ height: 20, opacity: 1 - i * 0.12 }} />
      ))}
    </div>
  );
}
