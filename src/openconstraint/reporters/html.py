"""Self-contained, offline HTML dashboard with clock and exception graph."""

from __future__ import annotations

import html
import json

from openconstraint.model import AuditResult


def _safe_json(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
    return (
        payload.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _adoption_section(result: AuditResult) -> str:
    adoption = result.summary.get("adoption")
    if not isinstance(adoption, dict):
        return ""
    source_lines: list[str] = []
    baseline_source = adoption.get("baseline_source")
    if isinstance(baseline_source, dict):
        producer = adoption.get("baseline_generated_by_version")
        producer_text = f" · producer OpenConstraint {html.escape(str(producer))}" if producer else ""
        source_lines.append(
            "Baseline: "
            f"<code>{html.escape(str(baseline_source['path']))}</code> "
            f"<small>sha256 {html.escape(str(baseline_source['sha256']))}{producer_text}</small>"
        )
    waiver_sources = adoption.get("waiver_sources")
    if isinstance(waiver_sources, list):
        for source in waiver_sources:
            if isinstance(source, dict):
                source_lines.append(
                    "Waivers: "
                    f"<code>{html.escape(str(source['path']))}</code> "
                    f"<small>sha256 {html.escape(str(source['sha256']))}</small>"
                )
    rows: list[str] = []
    dispositions = adoption.get("dispositions")
    if isinstance(dispositions, list):
        for disposition in dispositions:
            if not isinstance(disposition, dict) or not isinstance(disposition.get("diagnostic"), dict):
                continue
            finding = disposition["diagnostic"]
            location = finding["location"]
            status = str(disposition["status"])
            policy = html.escape(str(disposition["source_path"]))
            if status == "waived":
                expiry = f"; expires {disposition['expires']}" if disposition.get("expires") else ""
                policy = (
                    f"<b>{html.escape(str(disposition['waiver_id']))}</b>: "
                    f"{html.escape(str(disposition['reason']))}{html.escape(expiry)}"
                    f"<br><small>{policy}</small>"
                )
            rows.append(
                f'<tr data-severity="{html.escape(str(finding["severity"]))}" '
                f'data-mode="{html.escape(str(finding["mode"]))}">'
                f'<td><span class="pill {"warning" if status == "waived" else "note"}">'
                f"{html.escape(status)}</span></td>"
                f"<td><code>{html.escape(str(finding['rule_id']))}</code></td>"
                f"<td>{html.escape(str(finding['mode']))}</td>"
                f"<td><strong>{html.escape(str(finding['message']))}</strong>"
                f"<br><code>{html.escape(str(finding['fingerprint']))}</code></td>"
                f"<td>{policy}</td>"
                f"<td><code>{html.escape(str(location['path']))}:{int(location['line'])}</code></td></tr>"
            )
    strict = ""
    if adoption.get("strict_failure") is True:
        strict = (
            '<p class="control-failure"><b>Strict-control gate failed:</b> '
            f"{int(adoption['unused_waiver_count'])} unused waiver(s), "
            f"{int(adoption['stale_baseline_count'])} stale baseline entry/entries.</p>"
        )
    source_html = "<br>".join(source_lines) or "No external control source."
    body = (
        "".join(rows)
        if rows
        else '<tr><td colspan="6" class="empty">No diagnostics were waived or baselined.</td></tr>'
    )
    return f"""<section class="card table-card"><h2>Adoption controls</h2>
<p><b>{int(adoption["active_diagnostic_count"])}</b> active of <b>{int(adoption["raw_diagnostic_count"])}</b> raw findings;
<b>{int(adoption["waived_count"])}</b> waived and <b>{int(adoption["baselined_count"])}</b> baselined.
Unused waivers: <b>{int(adoption["unused_waiver_count"])}</b>; stale baseline entries: <b>{int(adoption["stale_baseline_count"])}</b>.</p>
<p>{source_html}</p>{strict}<div style="overflow:auto"><table><thead><tr><th>Status</th><th>Rule</th><th>Mode</th><th>Finding</th><th>Control</th><th>Location</th></tr></thead><tbody>{body}</tbody></table></div></section>"""


def render_html(result: AuditResult) -> str:
    data = result.to_dict()
    adoption_section = _adoption_section(result)
    mode_options = "".join(
        f'<option value="{html.escape(mode.name)}">{html.escape(mode.name)}</option>' for mode in result.modes
    )
    coverage_cards = "".join(
        f"""<article class="metric"><span>{html.escape(mode.name)}</span>
        <strong>{mode.coverage.score:.2f}%</strong><small>grade {mode.coverage.grade}</small></article>"""
        for mode in result.modes
    )
    finding_rows = "".join(
        f"""<tr data-severity="{finding.severity.value}" data-mode="{html.escape(finding.mode)}">
        <td><span class="pill {finding.severity.value}">{finding.severity.value}</span></td>
        <td><code>{finding.rule_id}</code></td><td>{html.escape(finding.mode)}</td>
        <td><strong>{html.escape(finding.message)}</strong><details><summary>Why and how to fix</summary>
        <p>{html.escape(finding.rationale)}</p><p><b>Remediation:</b> {html.escape(finding.suggestion)}</p>
        <p><b>Fingerprint:</b> <code>{finding.fingerprint}</code></p></details></td>
        <td><code>{html.escape(finding.location.path)}:{finding.location.line}</code></td></tr>"""
        for finding in result.diagnostics
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenConstraint report — {html.escape(str(result.design["top"]))}</title>
<style>
:root{{--bg:#07111f;--panel:#0d1b2a;--panel2:#12263a;--ink:#e8f0f8;--muted:#94a9bd;--line:#27445f;--cyan:#5eead4;--blue:#60a5fa;--amber:#fbbf24;--red:#fb7185;--violet:#c4b5fd}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 80% 0,#12365a 0,transparent 35%),var(--bg);color:var(--ink);font:14px/1.5 Inter,ui-sans-serif,system-ui,sans-serif}}
header,main{{max-width:1440px;margin:auto;padding:28px}}header{{display:flex;justify-content:space-between;align-items:end;border-bottom:1px solid var(--line)}}
h1{{font-size:30px;margin:0;letter-spacing:-.03em}}h1 em{{font-style:normal;color:var(--cyan)}}h2{{font-size:17px;margin:0 0 16px}}p{{color:var(--muted)}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:22px 0}}.metric{{background:linear-gradient(135deg,var(--panel2),var(--panel));border:1px solid var(--line);padding:16px;border-radius:12px}}
.metric span,.metric small{{display:block;color:var(--muted)}}.metric strong{{font-size:28px;color:var(--cyan)}}.grid{{display:grid;grid-template-columns:2fr 1fr;gap:16px}}
.card{{background:rgba(13,27,42,.92);border:1px solid var(--line);border-radius:14px;padding:18px;overflow:hidden}}#graph{{width:100%;height:520px;background:#081522;border-radius:10px}}
.legend{{display:flex;gap:15px;flex-wrap:wrap;color:var(--muted);margin:8px 0}}.dot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}}
select,input{{background:#081522;color:var(--ink);border:1px solid var(--line);border-radius:7px;padding:8px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:11px;text-align:left;border-bottom:1px solid #1d344a;vertical-align:top}}th{{color:var(--muted);font-size:12px;text-transform:uppercase}}
code{{color:#b9d9f7}}.pill{{padding:3px 7px;border-radius:999px;font-size:11px;font-weight:700}}.error{{color:#ffd5dc;background:#5b1824}}.warning{{color:#ffe8a3;background:#493a0f}}.note{{color:#d8d0ff;background:#30265a}}
.table-card{{margin-top:16px}}details summary{{cursor:pointer;color:var(--blue)}}.empty{{color:var(--muted);padding:20px}}footer{{max-width:1440px;margin:10px auto 30px;padding:0 28px;color:var(--muted)}}
.control-failure{{border-left:3px solid var(--red);padding-left:10px;color:#ffd5dc}}
@media(max-width:900px){{.grid{{grid-template-columns:1fr}}header{{display:block}}}}
</style></head><body>
<header><div><h1><em>Open</em>Constraint</h1><p>Deterministic SDC constraint-quality audit · {html.escape(str(result.design["top"]))}</p></div>
<div><b>{result.summary["errors"]}</b> errors · <b>{result.summary["warnings"]}</b> warnings · <b>{result.summary["notes"]}</b> notes</div></header>
<main><section class="metrics">{coverage_cards}</section>
<section class="grid"><article class="card"><div style="display:flex;justify-content:space-between"><h2>Clock & exception graph</h2><select id="mode">{mode_options}</select></div>
<div class="legend"><span><i class="dot" style="background:#5eead4"></i>clock</span><span><i class="dot" style="background:#60a5fa"></i>target</span><span><i class="dot" style="background:#c4b5fd"></i>sequential clock pin</span><span><i class="dot" style="background:#fbbf24"></i>exception</span></div><svg id="graph" role="img" aria-label="Clock and exception graph"></svg></article>
<article class="card"><h2>Design inventory</h2><p><b>{result.design["ports"]}</b> ports<br><b>{result.design["nets"]}</b> nets<br><b>{result.design["instances"]}</b> leaf cells<br><b>{result.design["sequential_instances"]}</b> sequential cells<br><b>{result.design["sequential_endpoints"]}</b> endpoints</p>
<h2>Coverage meaning</h2><p>Weighted structural obligations: clocked endpoints 50%, input delays 20%, output delays 20%, healthy queries 10%. Empty categories are omitted and weights renormalized.</p><p><b>100% is not sign-off.</b> It does not prove false paths are functionally impossible.</p></article></section>
<section class="card table-card"><div style="display:flex;justify-content:space-between;gap:10px"><h2>Findings</h2><input id="search" placeholder="Filter findings…" aria-label="Filter findings"></div>
<div style="overflow:auto"><table><thead><tr><th>Severity</th><th>Rule</th><th>Mode</th><th>Finding</th><th>Location</th></tr></thead><tbody id="findings">{finding_rows}</tbody></table></div></section>
{adoption_section}</main>
<footer>Generated by OpenConstraint {result.tool_version}. Report data is embedded locally; no telemetry or external assets.</footer>
<script id="report-data" type="application/json">{_safe_json(data)}</script>
<script>
const report=JSON.parse(document.getElementById('report-data').textContent);const svg=document.getElementById('graph');
const colors={{clock:'#5eead4',generated_clock:'#2dd4bf',target:'#60a5fa',sequential_clock_pin:'#c4b5fd',exception:'#fbbf24',scope:'#94a9bd'}};
function el(n,a={{}}){{const x=document.createElementNS('http://www.w3.org/2000/svg',n);for(const[k,v]of Object.entries(a))x.setAttribute(k,v);return x}}
function draw(){{const mode=report.modes.find(x=>x.name===document.getElementById('mode').value)||report.modes[0];svg.replaceChildren();if(!mode||!mode.graph.nodes.length){{const t=el('text',{{x:25,y:40,fill:'#94a9bd'}});t.textContent='No graph objects in this mode';svg.append(t);return}}
const box=svg.getBoundingClientRect(),w=Math.max(700,box.width),h=520;svg.setAttribute('viewBox',`0 0 ${{w}} ${{h}}`);const columns={{clock:0,generated_clock:1,target:2,sequential_clock_pin:3,scope:0,exception:2}};const grouped={{}};for(const n of mode.graph.nodes)(grouped[columns[n.kind]??1]??=[]).push(n);
const pos={{}};for(const [col,nodes]of Object.entries(grouped)){{nodes.sort((a,b)=>a.label.localeCompare(b.label));nodes.forEach((n,i)=>pos[n.id]={{x:70+(w-140)*(+col/3),y:45+(h-90)*((i+1)/(nodes.length+1))}})}}
for(const e of mode.graph.edges){{if(!pos[e.source]||!pos[e.target])continue;const p=el('path',{{d:`M${{pos[e.source].x}},${{pos[e.source].y}} C${{(pos[e.source].x+pos[e.target].x)/2}},${{pos[e.source].y}} ${{(pos[e.source].x+pos[e.target].x)/2}},${{pos[e.target].y}} ${{pos[e.target].x}},${{pos[e.target].y}}`,fill:'none',stroke:'#365a76','stroke-width':'1.3',opacity:'.8'}});svg.append(p)}}
for(const n of mode.graph.nodes){{const p=pos[n.id];if(!p)continue;const g=el('g',{{tabindex:'0'}}),c=el('circle',{{cx:p.x,cy:p.y,r:n.kind==='clock'?11:8,fill:colors[n.kind]||'#94a9bd',stroke:'#07111f','stroke-width':'3'}}),t=el('text',{{x:p.x+(p.x>w*.7?-12:13),y:p.y+4,fill:'#dbeafe','font-size':'11','text-anchor':p.x>w*.7?'end':'start'}});t.textContent=n.label.length>34?n.label.slice(0,31)+'…':n.label;const title=el('title');title.textContent=n.kind+': '+n.label;g.append(c,t,title);svg.append(g)}}}}
document.getElementById('mode').addEventListener('change',draw);window.addEventListener('resize',draw);draw();
document.getElementById('search').addEventListener('input',e=>{{const q=e.target.value.toLowerCase();for(const row of document.querySelectorAll('#findings tr'))row.hidden=!row.textContent.toLowerCase().includes(q)}});
</script></body></html>
"""
