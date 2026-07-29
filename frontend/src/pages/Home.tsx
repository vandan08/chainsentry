import { useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import heroPoster from "../asset/hero-poster.jpg";
import heroVideo from "../asset/chainserity.mp4";
import "../landing.css";

const REPO_URL = "https://github.com/vandan08/chainsentry";

/**
 * Marketing landing page — cinematic hero over the ambient loop, then a quiet
 * dark editorial page. Everything stated here is something the demo instance
 * actually does; the numbers come from the seeded world and the test suite.
 */

interface Row {
  cve: string;
  pkg: string;
  cvss: number;
  risk: number;
  kev?: boolean;
  scope: string;
  epss: string;
}

const FINDINGS: Row[] = [
  {
    cve: "CVE-2021-44228",
    pkg: "log4j-core 2.14.1",
    cvss: 10.0,
    risk: 98.4,
    kev: true,
    scope: "runtime",
    epss: "97.5%",
  },
  {
    cve: "CVE-2022-1471",
    pkg: "snakeyaml 1.30",
    cvss: 9.8,
    risk: 31.2,
    scope: "test only",
    epss: "1.2%",
  },
  {
    cve: "CVE-2023-44487",
    pkg: "netty-codec-http2 4.1.94",
    cvss: 7.5,
    risk: 88.1,
    kev: true,
    scope: "runtime",
    epss: "94.2%",
  },
  {
    cve: "CVE-2023-2976",
    pkg: "guava 30.1-jre",
    cvss: 7.1,
    risk: 24.6,
    scope: "runtime",
    epss: "0.3%",
  },
];

/** Plain-language claims — one line each, no vocabulary the reader has to look up. */
const PROMISES = [
  {
    claim: "You always know what to fix first.",
    because: "One ranked list, not three hundred alerts",
  },
  {
    claim: "Nothing risky ships by accident.",
    because: "The change is stopped before it goes out, not after",
  },
  {
    claim: "You can see exactly what a change brought in.",
    because: "The four new parts, not a nine-hundred-line inventory",
  },
  {
    claim: "Deciding to live with a risk is written down.",
    because: "Dated, attributed, and it expires on its own",
  },
  {
    claim: "Nobody has to learn a new tool.",
    because: "It shows up in the review your team already reads",
  },
];

const bySeverity = [...FINDINGS].sort((a, b) => b.cvss - a.cvss);
const byRisk = [...FINDINGS].sort((a, b) => b.risk - a.risk);

/** Fades sections in as they enter the viewport; a no-op under reduced motion. */
function useReveal() {
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const host = root.current;
    if (!host) return;
    const targets = Array.from(host.querySelectorAll<HTMLElement>("[data-reveal]"));
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      targets.forEach((el) => el.classList.add("in"));
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("in");
            io.unobserve(e.target);
          }
        });
      },
      { rootMargin: "0px 0px -12% 0px", threshold: 0.08 },
    );
    targets.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  return root;
}

function Mark() {
  return (
    <svg className="mark" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 4.5 5.5v6c0 4.5 3.1 8.4 7.5 10 4.4-1.6 7.5-5.5 7.5-10v-6L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="m8.5 12 2.4 2.4 4.6-4.8"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity=".75"
      />
    </svg>
  );
}

function Hero() {
  return (
    <header className="hero">
      <div className="hero-media" aria-hidden="true">
        <video
          className="hero-video"
          src={heroVideo}
          poster={heroPoster}
          autoPlay
          muted
          loop
          playsInline
          preload="auto"
        />
        <div className="hero-scrim" />
        <div className="hero-grain" />
      </div>

      <nav className="pill-nav" aria-label="Primary">
        <a href="#rank">How it works</a>
        <a href="#ships">Capabilities</a>
        <span className="pill-mark" aria-hidden="true">
          <Mark />
        </span>
        <a href="#promises">Why it matters</a>
        <a href={REPO_URL} target="_blank" rel="noreferrer">
          Source
        </a>
      </nav>

      <div className="hero-copy">
        <div className="hero-top">
          <div className="hero-lockup">
            <h1>ChainSentry</h1>
            <p className="hero-sub">Rank what&rsquo;s actually exploited.</p>
          </div>
          <Link className="hero-cta" to="/app">
            Open the live demo
          </Link>
        </div>

        <div className="hero-rule" />

        <div className="hero-base">
          <div className="hero-legal">
            <p className="hero-motto">Most criticals aren&rsquo;t urgent.</p>
            <p className="hero-copyright">ChainSentry ©2026 · seeded demo, read-only</p>
          </div>
          <div className="hero-blurb">
            <p>
              A supply-chain scanner that runs on every pull request — code, dependencies and
              container images, three engines in parallel, one deduplicated set of findings.
            </p>
            <p>
              Then it ranks them by CVSS × EPSS × CISA-KEV × dependency scope, and gates the merge on
              the one being exploited this week — not the twelve that aren&rsquo;t.
            </p>
          </div>
        </div>
      </div>
    </header>
  );
}

function Exhibit() {
  return (
    <div className="rerank">
      <div className="col">
        <div className="col-head">
          <span>Sorted by CVSS</span>
          <span>severity</span>
        </div>
        {bySeverity.map((f, i) => (
          <div className="row" key={f.cve} style={{ animationDelay: `${i * 70}ms` }}>
            <span className="rank">{i + 1}</span>
            <span>
              <span className="cve">{f.cve}</span>
              <span className="pkg">{f.pkg}</span>
            </span>
            <span className="score">{f.cvss.toFixed(1)}</span>
          </div>
        ))}
      </div>

      <div className="divider" aria-hidden>
        <span className="mark">same findings ↔ different order</span>
      </div>

      <div className="col after">
        <div className="col-head">
          <span>Sorted by ChainSentry risk</span>
          <span>exploitability</span>
        </div>
        {byRisk.map((f, i) => {
          const was = bySeverity.indexOf(f);
          const moved = was - i;
          return (
            <div
              className={`row ${moved > 0 ? "promoted" : moved < 0 ? "demoted" : ""}`}
              key={f.cve}
              style={{ animationDelay: `${280 + i * 70}ms` }}
            >
              <span className="rank">{i + 1}</span>
              <span>
                <span className="cve">
                  {f.cve}
                  {moved !== 0 && (
                    <span className={`move ${moved > 0 ? "up" : "down"}`}>
                      {moved > 0 ? "↑" : "↓"}
                      {Math.abs(moved)}
                    </span>
                  )}
                </span>
                <span className="pkg">{f.pkg}</span>
                <span className="tags">
                  {f.kev && <span className="kev-flag">🔥 KEV</span>}
                  <span className="engine-tag">EPSS {f.epss}</span>
                  <span className="engine-tag">{f.scope}</span>
                </span>
              </span>
              <span className="score">{f.risk.toFixed(1)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function Home() {
  const root = useReveal();

  return (
    <div className="landing" ref={root}>
      <Hero />

      <main className="landing-body">
        <section id="rank">
          <div className="section-head" data-reveal>
            <span className="idx">01</span>
            <h2>
              The same scan, <em>ranked two ways</em>
            </h2>
            <span className="aside">
              Severity says how bad a flaw could be. It says nothing about whether anyone is using it
              against you.
            </span>
          </div>
          <div data-reveal>
            <Exhibit />
          </div>
          <p className="rerank-caption" data-reveal>
            A 9.8 that only ever loads in tests drops to third; an HTTP/2 flaw scored 7.5 — in
            CISA&rsquo;s Known Exploited catalog, 94% chance of exploitation this month — climbs to
            second. That re-ordering is the whole product.
          </p>
        </section>

        <section id="how">
          <div className="section-head" data-reveal>
            <span className="idx">02</span>
            <h2>
              Scan, rank, <em>gate</em>
            </h2>
            <span className="aside">
              One webhook to first Check Run. A state machine on virtual threads, not a shell script.
            </span>
          </div>
          <div className="steps">
            <div className="step" data-reveal>
              <div className="n">1</div>
              <h3>Three engines, one clone</h3>
              <p>
                Trivy, Semgrep and Dependency-Check run in parallel against an ephemeral, read-only
                workspace, each behind a hard timeout.
              </p>
              <div className="detail">
                purl-keyed fingerprints collapse a CVE reported twice into one finding — both sources
                kept
              </div>
            </div>
            <div className="step" data-reveal style={{ transitionDelay: "80ms" }}>
              <div className="n">2</div>
              <h3>Scored by exploitability</h3>
              <p>
                CVSS, the daily EPSS feed, CISA-KEV membership and inferred dependency scope compose
                into one number. Weights are per-organization.
              </p>
              <div className="detail">feed updates re-rank stored findings instead of going stale</div>
            </div>
            <div className="step" data-reveal style={{ transitionDelay: "160ms" }}>
              <div className="n">3</div>
              <h3>Budget decides the merge</h3>
              <p>
                A <span className="mono">chainsentry.yml</span> in the repo declares the budget; the
                gate answers per rule, names the offenders, publishes a Check Run.
              </p>
              <div className="detail">
                repo policy overrides the platform default; suppressions expire and emit OpenVEX
              </div>
            </div>
          </div>
        </section>

        <section id="ships">
          <div className="section-head" data-reveal>
            <span className="idx">03</span>
            <h2>
              What <em>ships with it</em>
            </h2>
          </div>
          <div className="caps">
            {[
              {
                tag: "Pull requests",
                h: "SBOM diff, not SBOM dump",
                p: "CycloneDX stored per scan, base diffed against head — the four dependencies that changed, not 900 lines of inventory.",
              },
              {
                tag: "Policy as code",
                h: "Budgets that survive review",
                p: "Severity budgets and KEV bans evaluated server-side and in the runner, so one policy decides both the Check Run and the exit code.",
              },
              {
                tag: "Exceptions",
                h: "Suppressions with an expiry",
                p: "Accepting a risk writes a dated OpenVEX statement rather than a silent pass — and it lapses on its own.",
              },
              {
                tag: "Remediation",
                h: "Draft upgrade PRs",
                p: "Deterministic version bumps on a fresh branch. No LLM in the write path; it refuses rather than guess an ambiguous version.",
              },
              {
                tag: "Interoperability",
                h: "SARIF into code scanning",
                p: "Findings export as SARIF 2.1.0, adding a ranking layer to the tab a team already reads instead of demanding a new one.",
              },
              {
                tag: "Adoption",
                h: "Two ways in",
                p: "Install the GitHub App, or drop the composite Action into an existing workflow — it gates on its own if the platform is unreachable.",
              },
            ].map((c, i) => (
              <div className="cap" key={c.h} data-reveal style={{ transitionDelay: `${(i % 3) * 70}ms` }}>
                <div className="tag">{c.tag}</div>
                <h3>{c.h}</h3>
                <p>{c.p}</p>
              </div>
            ))}
          </div>
        </section>

        <section id="promises">
          <div className="section-head" data-reveal>
            <span className="idx">04</span>
            <h2>
              What it means <em>in practice</em>
            </h2>
            <span className="aside">
              No jargon. Five things that are true of a team once ChainSentry is switched on.
            </span>
          </div>
          <ul className="affirm">
            {PROMISES.map((p, i) => (
              <li key={p.claim} data-reveal style={{ transitionDelay: `${i * 70}ms` }}>
                <span className="tick" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none">
                    <path
                      d="m5 12.5 4.4 4.4L19 7.3"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </span>
                <span className="claim">{p.claim}</span>
                <span className="because">{p.because}</span>
              </li>
            ))}
          </ul>
        </section>

        <div className="closer" data-reveal>
          <h2>
            See it on a repo that&rsquo;s <em>actually broken</em>
          </h2>
          <p>
            Six repositories, twenty-three backdated scans. Start at{" "}
            <span className="mono">acme/payment-service</span> — PR #42 pulls in log4j-core 2.14.1,
            and the gate says no.
          </p>
          <div className="cta-row">
            <Link className="btn primary" to="/app">
              Open the dashboard <span className="arrow">→</span>
            </Link>
            <a className="btn ghost" href={REPO_URL} target="_blank" rel="noreferrer">
              Read the source
            </a>
          </div>
        </div>

        <footer>
          <span className="foot-brand">
            <Mark />
            ChainSentry
          </span>
          <a href={REPO_URL} target="_blank" rel="noreferrer">
            source
          </a>
          <a href={`${REPO_URL}/tree/main/docs`} target="_blank" rel="noreferrer">
            design docs
          </a>
          <a href="/api/v1/repos" target="_blank" rel="noreferrer">
            live API
          </a>
          <span className="foot-note">
            Demo data is seeded and reproducible — real scanner reports replayed through the real
            pipeline.
          </span>
        </footer>
      </main>
    </div>
  );
}
