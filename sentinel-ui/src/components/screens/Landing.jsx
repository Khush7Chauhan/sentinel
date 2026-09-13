import React, { useState, useRef } from "react";
import { IconLock, IconArrow, IconSearch } from "../common/Icons";
import { DEMO_DATA, CLEAN_DATA } from "../../data/mockData";

const GH_URL_RE = /^(https?:\/\/)?(www\.)?github\.com\/[\w.-]+\/[\w.-]+\/?$/i;

const TIMELINE = [
  { year: "2018", title: "event-stream", copy: "A popular npm package changed hands, and malicious code shipped to millions of installs before anyone noticed." },
  { year: "2020", title: "SolarWinds", copy: "Attackers compromised a build pipeline directly. The backdoor rode out through a routine, trusted update." },
  { year: "2024", title: "xz-utils", copy: "A patient maintainer takeover, two years in the making, nearly reached every major Linux distribution." },
];

export default function Landing({ onScan }) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [revealed, setRevealed] = useState(false);
  const inputRef = useRef(null);

  const reveal = () => {
    setRevealed(true);
    setTimeout(() => inputRef.current && inputRef.current.focus(), 200);
  };
  
  const scrollToTry = () => {
    reveal();
    document.getElementById("try")?.scrollIntoView({ behavior: "smooth", block: "center" });
  };
  
  const submit = () => {
    if (!GH_URL_RE.test(url.trim())) {
      setError("Enter a valid public GitHub URL — github.com/owner/repo");
      return;
    }
    setError("");
    onScan(url.trim().replace(/^https?:\/\//, "").replace(/^www\./, ""), DEMO_DATA);
  };

  return (
    <div className="future-page">
      <div className="future-nav">
        <div className="future-brand">
          <span className="future-brand-mark">🛡</span>
          Supply Chain Sentinel
        </div>
        <button className="future-nav-cta" onClick={scrollToTry}>Try now</button>
      </div>

      <div className="future-hero">
        <div className="future-glow" />
        <div className="future-badge"><span className="dot" /> Built for the TNL Hackathon</div>
        <div className="future-orb"><IconLock width="30" height="30" /></div>
        <h1>The trust you place in one package is the trust you place in all of them.</h1>
        <p className="sub">Every install pulls in code you didn't write, from people you've never met. Sentinel makes that trust visible — before it costs you.</p>
        <button className="cta-reveal-btn" onClick={scrollToTry}>Try now <IconArrow width="15" height="15" /></button>
      </div>

      <div className="future-section">
        <div className="future-eyebrow">It's already happened, more than once</div>
        <h2>The supply chain has been the target for years</h2>
        <div className="future-timeline">
          {TIMELINE.map((t) => (
            <div className="ft-item" key={t.year}>
              <div className="ft-dot">{t.year}</div>
              <div className="ft-body">
                <b>{t.title}</b>
                <span>{t.copy}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="future-section" style={{ paddingTop: 0 }}>
        <p className="future-tension">
          You shouldn't have to choose between <em>shipping fast</em> and <em>knowing what you shipped</em>.
        </p>
      </div>

      <div className="future-cta-section" id="try">
        <div className="future-eyebrow">See it on your own code</div>
        <h2 style={{ marginBottom: 26 }}>Scan a repo in seconds</h2>
        <div className="future-cta-glass">
          {!revealed && (
            <button className="cta-reveal-btn" onClick={reveal}>Try now <IconArrow width="15" height="15" /></button>
          )}
          <div className={`cta-input-wrap ${revealed ? "open" : ""}`}>
            <div className="cta-glass-pill">
              <IconSearch width="17" height="17" />
              <input
                ref={inputRef}
                placeholder="github.com/owner/repo"
                value={url}
                onChange={(e) => { setUrl(e.target.value); setError(""); }}
                onKeyDown={(e) => e.key === "Enter" && submit()}
              />
              <button onClick={submit}>Scan</button>
            </div>
            {error && <div className="cta-error">{error}</div>}
            <div className="cta-samples">
              <button onClick={() => onScan("acme/shopcart (demo-app)", DEMO_DATA)}>demo-app · planted threats</button>
              <button onClick={() => onScan("vercel/next.js (clean repo)", CLEAN_DATA)}>a clean repo</button>
            </div>
          </div>
        </div>
      </div>

      <div className="future-foot">
        Defensive analysis only — no exploits, no payloads. Demo data is simulated per hackathon rules.
      </div>
    </div>
  );
}