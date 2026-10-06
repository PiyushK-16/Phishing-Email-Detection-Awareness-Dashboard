// All dynamic text goes through esc() to prevent XSS (never innerHTML with raw input).
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path, opts) {
  const r = await fetch(path, opts); const t = await r.text();
  const j = t ? JSON.parse(t) : {};
  if (!r.ok) throw new Error(j.error || 'Request failed'); return j;
}
const cls = s => s > 70 ? 's-high' : s > 40 ? 's-sus' : s > 20 ? 's-mod' : 's-low';

document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('active', x === b));
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('hidden', t.id !== b.dataset.tab));
  if (b.dataset.tab === 'dashboard') loadDashboard();
  if (b.dataset.tab === 'history') loadHistory();
});

function renderResult(r, el) {
  const list = a => a.length ? '<ul>' + a.map(x => `<li>${esc(x)}</li>`).join('') + '</ul>' : '<p>None</p>';
  let h = `<div class="score ${cls(r.risk_score)}"><div class="big">${esc(r.risk_score)}/100</div><div><b>${esc(r.classification)}</b><br>
    <small>Rule score ${esc(r.rule_score)}${r.ml_probability != null ? ' · ML probability ' + Math.round(r.ml_probability * 100) + '% (not certainty)' : ''}</small></div></div>
    <h3>Why?</h3>` + (r.indicators.length ? '<ul>' + r.indicators.map(i => `<li>✓ ${esc(i.description)} <span class="tag ${esc(i.severity)}">${esc(i.severity)} · +${esc(i.points)}</span></li>`).join('') + '</ul>' : '<p>No indicators detected (this does not prove the email is safe).</p>');
  h += `<h3>Sender analysis (${esc(r.sender.score)}/100)</h3>` + list(r.sender.findings);
  h += '<h3>URL analysis</h3>' + (r.url_analyses.length ? r.url_analyses.map(u => `<p><code>${esc(u.url)}</code> — ${esc(u.score)}/100</p>` + list(u.findings)).join('') : '<p>No URLs found.</p>');
  h += `<h3>Attachment</h3>` + (r.attachment.extension || r.attachment.findings.length ? `<p>Risk: ${esc(r.attachment.risk)}</p>` + list(r.attachment.findings) : '<p>None supplied.</p>');
  h += '<h3>Recommended actions</h3>' + list(r.recommendations) + `<p class="note">${esc(r.note || '')}</p>`;
  el.innerHTML = h;
}

$('#go').onclick = async () => {
  $('#err').textContent = '';
  try {
    const r = await api('/api/analyze', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({sender: $('#sender').value, subject: $('#subject').value, body: $('#body').value, attachment_name: $('#att').value})});
    renderResult(r, $('#result'));
  } catch (e) { $('#err').textContent = e.message; }
};
const fill = (s, sub, b, a) => { $('#sender').value = s; $('#subject').value = sub; $('#body').value = b; $('#att').value = a; };
$('#s1').onclick = () => fill('Security Alert <security-alert@account-check.invalid.test>', 'URGENT: Verify Your Account Immediately',
  'Dear customer, your account will be suspended within 24 hours. Verify your password now: http://198.51.100.10/verify-account', '');
$('#s2').onclick = () => fill('Example Training Team <training@example.org>', 'Cybersecurity Workshop Reminder',
  'Hi team, a reminder that the cybersecurity workshop is on Friday at 14:00 in room 12. Agenda attached.', 'agenda.pdf');
$('#file').onchange = e => {
  const f = e.target.files[0]; if (!f) return;
  if (!/\.(txt|eml)$/i.test(f.name) || f.size > 200000) { $('#err').textContent = 'Only .txt/.eml files up to 200 KB.'; return; }
  const rd = new FileReader();
  rd.onload = () => {
    const t = String(rd.result), i = t.search(/\r?\n\r?\n/), head = i > 0 ? t.slice(0, i) : '';
    const g = n => ((head.match(new RegExp('^' + n + ':\\s*(.*)$', 'im')) || [])[1] || '').trim();
    $('#sender').value = g('From'); $('#subject').value = g('Subject'); $('#body').value = head ? t.slice(i).trim() : t;
  };
  rd.readAsText(f);
};

const charts = {}, PAL = ['#2e7d32', '#f9a825', '#ef6c00', '#c62828', '#14213d', '#fca311', '#6a1b9a', '#00838f'];
function chart(id, type, labels, data, label) {
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart($('#' + id), {type: type === 'hbar' ? 'bar' : type,
    data: {labels, datasets: [{label, data, backgroundColor: PAL, borderColor: '#14213d'}]},
    options: {indexAxis: type === 'hbar' ? 'y' : 'x', plugins: {legend: {display: type === 'doughnut'}}}});
}
async function loadDashboard() {
  const [s, i] = await Promise.all([api('/api/dashboard/stats'), api('/api/dashboard/indicators')]);
  const c = s.by_class, g = k => c[k] || 0;
  const card = (t, v) => `<div class="card"><b>${esc(v)}</b>${esc(t)}</div>`;
  $('#cards').innerHTML = card('Total analyzed', s.total) + card('Likely phishing', g('HIGH RISK / LIKELY PHISHING')) +
    card('Suspicious / moderate', g('SUSPICIOUS') + g('MODERATE RISK')) + card('Low risk', g('LOW RISK')) + card('Average risk score', s.avg_score);
  chart('c1', 'doughnut', Object.keys(c), Object.values(c), 'Emails');
  chart('c2', 'bar', ['Flagged (score > 40)', 'Not flagged'], [s.flagged.flagged, s.flagged.not_flagged], 'Emails');
  chart('c3', 'hbar', i.indicators.map(x => x.description.slice(0, 40)), i.indicators.map(x => x.count), 'Count');
  chart('c4', 'bar', s.histogram.map(x => x.bucket), s.histogram.map(x => x.count), 'Emails');
  chart('c5', 'line', s.trend.map(x => x.day), s.trend.map(x => x.count), 'Analyses');
  chart('c6', 'hbar', i.keywords.map(x => x.keyword), i.keywords.map(x => x.count), 'Count');
}
async function loadHistory() {
  const p = new URLSearchParams({q: $('#q').value, classification: $('#fc').value, sort: $('#sort').value});
  const rows = await api('/api/analyses?' + p);
  const tb = $('#rows'); tb.innerHTML = '';
  rows.forEach(r => {
    const tr = document.createElement('tr');
    [r.analysis_id, r.sender_domain, r.subject, r.risk_score, r.classification, r.created_at].forEach(v => {
      const td = document.createElement('td'); td.textContent = v; tr.appendChild(td); });
    const td = document.createElement('td');
    const v = document.createElement('button'); v.textContent = 'View'; v.onclick = () => viewOne(r.analysis_id);
    const d = document.createElement('button'); d.textContent = 'Delete'; d.onclick = async () => { await api('/api/analyses/' + r.analysis_id, {method: 'DELETE'}); loadHistory(); };
    td.append(v, d); tr.appendChild(td); tb.appendChild(tr);
  });
}
async function viewOne(id) {
  const a = await api('/api/analyses/' + id), el = $('#detail');
  el.innerHTML = `<h3>Analysis #${esc(a.analysis_id)} — ${esc(a.classification)} (${esc(a.risk_score)}/100)</h3><ul>` +
    a.indicators.filter(x => x.indicator_type !== 'keyword').map(x => `<li>${esc(x.description)}</li>`).join('') + '</ul>' +
    a.url_analyses.map(u => `<p><code>${esc(u.url_safe_representation)}</code> ${esc(u.risk_score)}/100 – ${esc(u.findings)}</p>`).join('');
}
$('#reload').onclick = loadHistory;
