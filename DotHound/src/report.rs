use crate::capture::{CaptureGraph, CapturedExchange, ExchangeKind};
use std::io;

/// Renders a `CaptureGraph` as a self-contained HTML page and writes
/// it to `writer`.
pub fn write_html_report(graph: &CaptureGraph, writer: &mut impl io::Write) -> io::Result<()> {
    write!(
        writer,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DotHound Workflow Report</title>
<style>
:root {{
    --bg: #0b0f17;
    --surface: #151b26;
    --border: #253147;
    --text: #c9d1d9;
    --muted: #6e7681;
    --accent: #58a6ff;
    --green: #3fb950;
    --red: #f85149;
    --orange: #d29922;
    --purple: #a371f7;
    --pink: #db61a2;
    --radius: 8px;
    --mono: 'SF Mono', 'Cascadia Code', 'JetBrains Mono', 'Fira Code', monospace;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1100px;
    margin: 0 auto;
}}
header {{
    text-align: center;
    margin-bottom: 2.5rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
}}
header h1 {{
    font-size: 1.8rem;
    font-weight: 700;
    letter-spacing: -0.5px;
    color: #fff;
}}
header h1 span {{ color: var(--accent); }}
header .subtitle {{
    color: var(--muted);
    font-size: 0.88rem;
    margin-top: 0.35rem;
}}

/* ── summary cards ───────────────────────────────────────────── */
.summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem;
    margin-bottom: 2.5rem;
}}
.card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.2rem 1rem;
    text-align: center;
}}
.card .value {{
    font-size: 2rem;
    font-weight: 700;
    color: #fff;
    line-height: 1;
}}
.card .label {{
    font-size: 0.78rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 0.5rem;
}}
.card.http .value {{ color: var(--green); }}
.card.tunnel .value {{ color: var(--purple); }}
.card.duration .value {{ font-size: 1.3rem; color: var(--orange); }}

/* ── redaction badge ─────────────────────────────────────────── */
.redaction-badge {{
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 99px;
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    margin-bottom: 2rem;
}}
.redaction-badge.redacted {{ background: #1a3a2a; color: var(--green); }}
.redaction-badge.raw {{ background: #3a1a1a; color: var(--red); }}

/* ── timeline ────────────────────────────────────────────────── */
.timeline {{ position: relative; padding-left: 2.5rem; }}
.timeline::before {{
    content: '';
    position: absolute;
    left: 0.85rem;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--border);
}}
.step {{
    position: relative;
    margin-bottom: 1.5rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
}}
.step::before {{
    content: '';
    position: absolute;
    left: -1.65rem;
    top: 1.3rem;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--border);
    border: 2px solid var(--bg);
    z-index: 1;
}}
.step.http::before {{ background: var(--green); box-shadow: 0 0 6px rgba(63,185,80,0.5); }}
.step.tunnel::before {{ background: var(--purple); box-shadow: 0 0 6px rgba(163,113,247,0.5); }}

.step-header {{
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.9rem 1.2rem;
    cursor: pointer;
    user-select: none;
    transition: background 0.15s;
}}
.step-header:hover {{ background: rgba(255,255,255,0.03); }}

.method {{
    display: inline-block;
    font-family: var(--mono);
    font-size: 0.78rem;
    font-weight: 700;
    padding: 0.25rem 0.6rem;
    border-radius: 4px;
    min-width: 60px;
    text-align: center;
    letter-spacing: 0.5px;
}}
.method.GET {{ background: #1a3a2a; color: var(--green); }}
.method.POST {{ background: #1a2a3a; color: var(--accent); }}
.method.PUT {{ background: #3a351a; color: var(--orange); }}
.method.DELETE {{ background: #3a1a1a; color: var(--red); }}
.method.PATCH {{ background: #3a2a1a; color: var(--orange); }}
.method.CONNECT {{ background: #2a1a3a; color: var(--purple); }}

.step-target {{
    flex: 1;
    font-family: var(--mono);
    font-size: 0.82rem;
    color: var(--text);
    word-break: break-all;
    min-width: 0;
}}
.step-meta {{
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 0.78rem;
    color: var(--muted);
    white-space: nowrap;
}}
.status {{
    font-weight: 700;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-family: var(--mono);
}}
.status-2xx {{ background: #1a3a2a; color: var(--green); }}
.status-3xx {{ background: #3a351a; color: var(--orange); }}
.status-4xx {{ background: #3a1a1a; color: var(--red); }}
.status-5xx {{ background: #3a1a1a; color: var(--red); }}

.chevron {{
    font-size: 0.7rem;
    transition: transform 0.2s;
    color: var(--muted);
}}
.step.open .chevron {{ transform: rotate(180deg); }}

/* ── step body (expandable) ──────────────────────────────────── */
.step-body {{
    display: none;
    border-top: 1px solid var(--border);
    padding: 1.2rem;
}}
.step.open .step-body {{ display: block; }}

.pane-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
}}
@media (max-width: 700px) {{
    .pane-grid {{ grid-template-columns: 1fr; }}
}}
.pane {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
}}
.pane-title {{
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--muted);
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
    background: rgba(255,255,255,0.02);
}}
.pane-content {{ padding: 0.6rem 0.75rem; font-size: 0.8rem; }}

/* ── headers table ───────────────────────────────────────────── */
.kv-table {{ width: 100%; border-collapse: collapse; }}
.kv-table td {{
    padding: 0.25rem 0;
    vertical-align: top;
    font-family: var(--mono);
    font-size: 0.75rem;
    border-bottom: 1px solid rgba(255,255,255,0.03);
}}
.kv-table .key {{
    color: var(--purple);
    white-space: nowrap;
    padding-right: 0.75rem;
    width: 1%;
}}
.kv-table .val {{
    color: var(--text);
    word-break: break-all;
}}
.kv-table .val.redacted {{
    color: var(--red);
    font-style: italic;
}}

/* ── body preview ────────────────────────────────────────────── */
.body-preview {{
    font-family: var(--mono);
    font-size: 0.73rem;
    background: rgba(0,0,0,0.3);
    padding: 0.6rem 0.75rem;
    border-radius: 4px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 300px;
    overflow-y: auto;
    color: var(--text);
}}
.body-preview.redacted {{ color: var(--red); font-style: italic; }}
.json-key {{ color: var(--purple); }}
.json-string {{ color: var(--green); }}
.json-number {{ color: var(--accent); }}
.json-bool {{ color: var(--orange); }}

/* ── notes ───────────────────────────────────────────────────── */
.notes {{
    margin-top: 0.75rem;
    padding: 0.5rem 0.75rem;
    background: rgba(88,166,255,0.06);
    border-left: 3px solid var(--accent);
    border-radius: 0 var(--radius) var(--radius) 0;
    font-size: 0.78rem;
    color: var(--muted);
}}

/* ── footer ──────────────────────────────────────────────────── */
footer {{
    text-align: center;
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.75rem;
}}
</style>
</head>
<body>

<header>
  <h1>DotHound <span>Workflow Report</span></h1>
  <div class="subtitle">{start_url}</div>
</header>

<div class="summary-grid">
  <div class="card">
    <div class="value">{total_exchanges}</div>
    <div class="label">Total Exchanges</div>
  </div>
  <div class="card http">
    <div class="value">{http_exchanges}</div>
    <div class="label">HTTP Exchanges</div>
  </div>
  <div class="card tunnel">
    <div class="value">{https_tunnels}</div>
    <div class="label">HTTPS Tunnels</div>
  </div>
  <div class="card duration">
    <div class="value">{duration}</div>
    <div class="label">Duration</div>
  </div>
</div>

<div class="redaction-badge {badge_class}">{badge_label}</div>

<div class="timeline">
"#,
        start_url = html_escape(&graph.start_url),
        total_exchanges = graph.summary.total_exchanges,
        http_exchanges = graph.summary.http_exchanges,
        https_tunnels = graph.summary.https_tunnels,
        duration = format_duration(graph),
        badge_class = if graph.redaction.sensitive_values_included {
            "raw"
        } else {
            "redacted"
        },
        badge_label = if graph.redaction.sensitive_values_included {
            "Secrets Visible"
        } else {
            "Sensitive Values Redacted"
        },
    )?;

    // ── Render each node / exchange ────────────────────────────────
    for node in &graph.nodes {
        let exchange = graph.exchanges.iter().find(|ex| ex.id == node.exchange_id);

        render_step(writer, node, exchange)?;
    }

    write!(
        writer,
        r#"</div><!-- .timeline -->

<footer>
  Generated by {generated_by} &middot; schema {schema}
  &middot; {started_at} &rarr; {completed_at}
</footer>

<script>
document.querySelectorAll('.step-header').forEach(header => {{
  header.addEventListener('click', () => {{
    header.parentElement.classList.toggle('open');
  }});
}});

// Auto-open the first step
const first = document.querySelector('.step');
if (first) first.classList.add('open');
</script>
</body>
</html>"#,
        generated_by = html_escape(graph.generated_by),
        schema = graph.schema,
        started_at = format_unix_ms(graph.started_at_unix_ms),
        completed_at = graph
            .completed_at_unix_ms
            .map(format_unix_ms)
            .unwrap_or_else(|| "—".to_owned()),
    )?;

    Ok(())
}

// ── step rendering ─────────────────────────────────────────────────

fn render_step(
    writer: &mut impl io::Write,
    node: &crate::capture::WorkflowNode,
    exchange: Option<&CapturedExchange>,
) -> io::Result<()> {
    let (method, target) = split_label(&node.label);
    let kind_class = match node.kind {
        ExchangeKind::Http => "http",
        ExchangeKind::HttpsTunnel => "tunnel",
    };

    let status_code = exchange
        .as_ref()
        .and_then(|ex| ex.response.as_ref())
        .map(|r| r.status_code);
    let status_class = status_code
        .map(|c| match c {
            200..=299 => "status-2xx",
            300..=399 => "status-3xx",
            400..=499 => "status-4xx",
            _ => "status-5xx",
        })
        .unwrap_or("");

    let response_size = exchange
        .as_ref()
        .and_then(|ex| ex.response.as_ref())
        .and_then(|r| r.body.as_ref())
        .map(|b| format_size(b.bytes_seen))
        .unwrap_or_else(|| "—".to_owned());

    let duration = exchange
        .map(|ex| {
            let ms = ex.finished_at_unix_ms.saturating_sub(ex.started_at_unix_ms);
            format!("{ms}ms")
        })
        .unwrap_or_else(|| "—".to_owned());

    let target_display = truncate_target(&target, 70);

    write!(
        writer,
        r#"<div class="step {kind_class}">
  <div class="step-header">
    <span class="method {method}">{method}</span>
    <span class="step-target" title="{target_full}">{target_display}</span>
    <span class="step-meta">
      <span class="status {status_class}">{status_code}</span>
      <span>{response_size}</span>
      <span>{duration}</span>
      <span class="chevron">&#9660;</span>
    </span>
  </div>
  <div class="step-body">
    <div class="pane-grid">
"#,
        kind_class = kind_class,
        method = method,
        target_display = html_escape(&target_display),
        target_full = html_escape(&target),
        status_code = status_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "—".to_owned()),
        status_class = status_class,
        response_size = response_size,
        duration = duration,
    )?;

    // Request pane
    if let Some(ex) = exchange {
        render_request_pane(writer, ex)?;
        render_response_pane(writer, ex)?;
    }

    write!(writer, "    </div><!-- .pane-grid -->\n")?;

    // Notes
    if let Some(ex) = exchange {
        if !ex.notes.is_empty() {
            write!(writer, r#"    <div class="notes">"#)?;
            for note in &ex.notes {
                write!(writer, "{} ", html_escape(note))?;
            }
            write!(writer, "</div>\n")?;
        }
    }

    write!(
        writer,
        "  </div><!-- .step-body -->\n</div><!-- .step -->\n"
    )?;

    Ok(())
}

fn render_request_pane(writer: &mut impl io::Write, exchange: &CapturedExchange) -> io::Result<()> {
    write!(
        writer,
        r#"      <div class="pane">
        <div class="pane-title">Request &mdash; {method} {version}</div>
        <div class="pane-content">
"#,
        method = html_escape(&exchange.request.method),
        version = html_escape(&exchange.request.version),
    )?;

    render_headers(writer, &exchange.request.headers)?;
    render_body(writer, exchange.request.body.as_ref())?;

    write!(writer, "        </div>\n      </div>\n")?;
    Ok(())
}

fn render_response_pane(
    writer: &mut impl io::Write,
    exchange: &CapturedExchange,
) -> io::Result<()> {
    let (status, reason, version, headers, body) = match &exchange.response {
        Some(resp) => (
            resp.status_code.to_string(),
            resp.reason.clone(),
            resp.version.clone(),
            resp.headers.as_slice(),
            resp.body.as_ref(),
        ),
        None => (
            "—".to_owned(),
            "No response captured".to_owned(),
            "—".to_owned(),
            &[][..],
            None,
        ),
    };

    write!(
        writer,
        r#"      <div class="pane">
        <div class="pane-title">Response &mdash; {status} {reason} &mdash; {version}</div>
        <div class="pane-content">
"#,
        status = html_escape(&status),
        reason = html_escape(&reason),
        version = html_escape(&version),
    )?;

    render_headers(writer, headers)?;
    render_body(writer, body)?;

    write!(writer, "        </div>\n      </div>\n")?;
    Ok(())
}

fn render_headers(
    writer: &mut impl io::Write,
    headers: &[crate::capture::CapturedHeader],
) -> io::Result<()> {
    if headers.is_empty() {
        write!(
            writer,
            r#"          <div style="color:var(--muted);font-size:0.75rem;">(no headers)</div>"#
        )?;
        return Ok(());
    }

    write!(writer, r#"          <table class="kv-table">"#)?;
    for h in headers {
        let val_class = if h.sensitive { "redacted" } else { "" };
        let sha = h
            .value_sha256
            .as_deref()
            .map(|s| {
                format!(
                    " <span style='color:var(--muted);font-size:0.65rem;'>(sha256:{})</span>",
                    &s[..12]
                )
            })
            .unwrap_or_default();
        write!(
            writer,
            r#"<tr><td class="key">{}</td><td class="val {}">{}{}</td></tr>"#,
            html_escape(&h.name),
            val_class,
            html_escape(&h.value),
            sha,
        )?;
    }
    write!(writer, "</table>\n")?;
    Ok(())
}

fn render_body(
    writer: &mut impl io::Write,
    body: Option<&crate::capture::CapturedBody>,
) -> io::Result<()> {
    let Some(body) = body else {
        write!(
            writer,
            r#"          <div style="color:var(--muted);font-size:0.75rem;margin-top:0.5rem;">(no body)</div>"#
        )?;
        return Ok(());
    };

    let body_class = if body.sensitive { "redacted" } else { "" };
    let text = body.text.as_deref().unwrap_or("<binary body>");
    let truncated_note = if body.truncated {
        format!(
            " <span style='color:var(--orange);font-size:0.65rem;'>(truncated: {} / {} bytes)</span>",
            body.bytes_captured, body.bytes_seen
        )
    } else {
        String::new()
    };

    let content_type_str = body.content_type.as_deref().unwrap_or("unknown");

    write!(
        writer,
        r#"          <div style="margin-top:0.5rem;font-size:0.65rem;color:var(--muted);">Content-Type: {ct}</div>
          <div class="body-preview {body_class}">{text}</div>
          <div style="font-size:0.65rem;color:var(--muted);margin-top:0.25rem;">{size_info}{truncated_note}</div>
"#,
        ct = html_escape(content_type_str),
        body_class = body_class,
        text = highlight_json(&html_escape(text)),
        size_info = format!(
            "{} bytes captured / {} bytes seen",
            body.bytes_captured, body.bytes_seen
        ),
        truncated_note = truncated_note,
    )?;

    Ok(())
}

// ── helpers ────────────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn format_duration(graph: &CaptureGraph) -> String {
    let Some(end) = graph.completed_at_unix_ms else {
        return "—".to_owned();
    };
    let ms = end.saturating_sub(graph.started_at_unix_ms);

    if ms < 1_000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        let secs = ms / 1000;
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

fn format_unix_ms(ms: u128) -> String {
    // Very simple ISO-like formatting (UTC).
    let secs = (ms / 1000) as i64;
    let millis = (ms % 1000) as u32;

    // Use a fixed offset from Unix epoch – rough but works without chrono.
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate date from days since epoch (good enough for display).
    // This is approximate – skips leap seconds, etc. but is dependency-free.
    let (year, month, day) = days_to_ymd(days_since_epoch as i64);

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}.{millis:03} UTC")
}

fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Algorithm from Howard Hinnant – public domain.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as i64;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as i64;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn split_label(label: &str) -> (String, String) {
    let parts: Vec<&str> = label.splitn(2, ' ').collect();
    if parts.len() == 2 {
        (parts[0].to_owned(), parts[1].to_owned())
    } else {
        ("GET".to_owned(), label.to_owned())
    }
}

fn truncate_target(target: &str, max_len: usize) -> String {
    if target.len() <= max_len {
        return target.to_owned();
    }
    let head = &target[..max_len.saturating_sub(3).min(target.len())];
    format!("{head}...")
}

/// Naive JSON syntax highlighting for body previews.
fn highlight_json(text: &str) -> String {
    // Only try to highlight if it looks like JSON
    let trimmed = text.trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return text.to_owned();
    }

    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escape = false;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if escape {
            in_string = true;
            escape = false;
            out.push(ch);
            i += 1;
            continue;
        }

        if ch == '\\' && in_string {
            escape = true;
            out.push(ch);
            i += 1;
            continue;
        }

        if ch == '"' {
            in_string = !in_string;
            out.push_str(r#"<span class="json-key">"#);
            out.push(ch);
            out.push_str("</span>");
            i += 1;
            continue;
        }

        if in_string {
            out.push(ch);
        } else if ch == '{' || ch == '}' || ch == '[' || ch == ']' {
            out.push(ch);
        } else if ch == ':' {
            out.push(ch);
            // After a colon, look ahead for the next value
            let rest: String = chars[i + 1..].iter().collect();
            let val = rest.trim_start();
            if val.starts_with('"') {
                // Next is a string
                out.push_str(r#"<span class="json-string">"#);
                // Find closing quote
                let mut j = i + 1;
                let mut escaped = false;
                while j < chars.len() {
                    if escaped {
                        escaped = false;
                        j += 1;
                        continue;
                    }
                    if chars[j] == '\\' {
                        escaped = true;
                        j += 1;
                        continue;
                    }
                    if chars[j] == '"' {
                        break;
                    }
                    j += 1;
                }
                // Push the value (already in raw form, we'll close span later)
                while i < j {
                    i += 1;
                    out.push(chars[i]);
                }
                i += 1; // skip closing quote
                out.push('"');
                out.push_str("</span>");
                continue;
            } else if val.starts_with(|c: char| c.is_ascii_digit() || c == '-') {
                out.push_str(r#"<span class="json-number">"#);
                let mut j = i + 1;
                while j < chars.len()
                    && (chars[j].is_ascii_digit()
                        || chars[j] == '.'
                        || chars[j] == '-'
                        || chars[j] == 'e'
                        || chars[j] == 'E')
                {
                    j += 1;
                }
                while i < j - 1 {
                    i += 1;
                    out.push(chars[i]);
                }
                out.push_str("</span>");
                continue;
            } else if val.starts_with("true") || val.starts_with("false") {
                out.push_str(r#"<span class="json-bool">"#);
                let len = if val.starts_with("true") { 4 } else { 5 };
                for _ in 0..len {
                    i += 1;
                    out.push(chars[i]);
                }
                out.push_str("</span>");
                continue;
            } else if val.starts_with("null") {
                out.push_str(r#"<span class="json-bool">"#);
                for _ in 0..4 {
                    i += 1;
                    out.push(chars[i]);
                }
                out.push_str("</span>");
                continue;
            }
        }

        i += 1;
    }

    out
}
