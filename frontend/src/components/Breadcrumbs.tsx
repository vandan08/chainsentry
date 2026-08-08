import { Fragment } from "react";
import { Link } from "react-router-dom";

export interface Crumb {
  label: string;
  to?: string;
}

export function Breadcrumbs({ trail }: { trail: Crumb[] }) {
  return (
    <nav className="breadcrumbs" aria-label="breadcrumb">
      {trail.map((crumb, i) => (
        <Fragment key={i}>
          {i > 0 && <span className="sep">▸</span>}
          {crumb.to ? (
            <Link to={crumb.to}>{crumb.label}</Link>
          ) : (
            <span className="current">{crumb.label}</span>
          )}
        </Fragment>
      ))}
    </nav>
  );
}
