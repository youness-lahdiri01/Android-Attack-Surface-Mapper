/**
 * app.js — Main controller
 * 100% local — no API key required.
 */

// ── Helpers ───────────────────────────────────────────────────────────────────

function $(id){ return document.getElementById(id); }

function switchTab(t){
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(el => el.classList.remove('active'));
  document.querySelector(`.tab[onclick="switchTab('${t}')"]`).classList.add('active');
  $('tab-'+t).classList.add('active');
}

function setStatus(msg, color){
  const el = $('status-msg');
  el.textContent = msg;
  el.style.color = color || 'var(--text2)';
  el.style.display = msg ? 'block' : 'none';
}

function setBusy(busy){
  const btn  = document.querySelector('.btn-primary');
  const spin = $('scan-spin');
  btn.disabled = busy;
  spin.style.display = busy ? 'inline-block' : 'none';
}

function clearAll(){
  $('xml-input').value = '';
  $('apk-strip').style.display = 'none';
  $('app-badge').style.display = 'none';
  $('risk-badge').style.display = 'none';
  setStatus('');
  $('comp-body').innerHTML = '<tr><td colspan="6"><div class="empty">Run a scan first</div></td></tr>';
  $('findings-body').innerHTML = '<div class="empty">Run a scan first</div>';
  $('report-body').innerHTML = '<div class="empty">Run a scan to generate a report</div>';
  $('graph-svg').innerHTML = '<text x="330" y="105" text-anchor="middle" style="fill:var(--text3);font-size:12px;font-family:monospace">Run a scan to generate the graph</text>';
  $('mermaid-box').textContent = '— run scan first —';
  $('stat-grid').innerHTML = '';
}

// ── Demo manifest ─────────────────────────────────────────────────────────────

const DEMO_XML = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerablebank">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <application android:allowBackup="true" android:debuggable="true" android:label="VulnerableBank">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name=".LoginActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="bank" android:host="login"/>
            </intent-filter>
        </activity>
        <activity android:name=".TransferActivity" android:exported="true"/>
        <activity android:name=".AdminActivity" android:exported="true"
            android:permission="com.example.permission.ADMIN"/>
        <service android:name=".DataSyncService" android:exported="true"/>
        <service android:name=".PaymentService" android:exported="false"/>
        <receiver android:name=".SmsReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
        <provider android:name=".UserDataProvider"
            android:authorities="com.example.vulnerablebank.provider"
            android:exported="true"/>
        <provider android:name=".FileProvider"
            android:authorities="com.example.vulnerablebank.files"
            android:exported="false" android:grantUriPermissions="true"/>
    </application>
</manifest>`;

function loadDemo(){
  $('xml-input').value = DEMO_XML;
  setStatus('Demo manifest loaded — click Scan manifest', 'var(--blue)');
}

// ── APK drag & drop ───────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const zone = $('drop-zone');
  if (!zone) return;

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('over');
    const f = e.dataTransfer.files[0];
    if (f) handleAPK(f);
  });
  zone.addEventListener('click', () => $('apk-input').click());
});

function setDZProgress(msg){
  const el = $('dz-progress');
  if (msg){ el.textContent = msg; el.style.display = 'block'; }
  else el.style.display = 'none';
}

function showAPKStrip(info){
  const el = $('apk-strip');
  el.style.display = 'flex';
  el.innerHTML = [
    ['File', info.fileName],
    ['Size', info.fileSize],
    ['DEX', info.dexCount],
    ['Native', info.nativeArchs],
    ['Files', info.totalFiles],
  ].map(([l,v]) => `<div class="api"><span class="api-l">${l}</span><span class="api-v">${v}</span></div>`).join('')
   + `<span class="badge badge-green" style="margin-left:auto">APK loaded ✓</span>`;
}

async function handleAPK(file){
  if (!file) return;
  if (!file.name.endsWith('.apk')){
    setStatus('Please select a .apk file', 'var(--red)');
    return;
  }

  $('drop-zone').style.pointerEvents = 'none';
  setDZProgress('Loading…');
  setStatus('');

  try {
    const { xml, apkInfo } = await APKLoader.load(file, msg => setDZProgress(msg));
    $('xml-input').value = xml;
    showAPKStrip(apkInfo);
    setDZProgress('');
    setStatus(`✓ Manifest extracted from ${file.name}`, 'var(--green)');

    // auto-scan
    await analyzeXML();

  } catch(err) {
    setDZProgress('');
    setStatus('APK Error: ' + err.message, 'var(--red)');
    console.error('[handleAPK]', err);
  } finally {
    $('drop-zone').style.pointerEvents = '';
  }
}

// ── Render helpers ─────────────────────────────────────────────────────────────

const TYPE_CLS = { Activity:'ta', Service:'ts', Receiver:'tr', Provider:'tam' };

function riskDots(score){
  const lvl = riskLevel(score);
  const map  = { critical:{c:'r',n:3}, high:{c:'a',n:2}, medium:{c:'g',n:1}, low:{c:'',n:0} };
  const {c, n} = map[lvl] || map.low;
  return '<div class="rdots">' + [0,1,2].map(i=>`<div class="rd ${i<n?c:''}"></div>`).join('') + '</div>';
}

function renderComponents(components){
  const tbody = $('comp-body');
  if (!components.length){
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty">No components found</div></td></tr>';
    return;
  }

  const exp    = components.filter(c => c.inferredExported);
  const noPerm = exp.filter(c => !c.perm);
  const ints   = exp.filter(c => c.actions.length > 0);

  $('stat-grid').innerHTML = [
    ['Total',    components.length, ''],
    ['Exported', exp.length,        'var(--red)'],
    ['No Perm',  noPerm.length,     'var(--amber)'],
    ['Intents',  ints.length,       'var(--blue)'],
  ].map(([l,v,col]) => `
    <div class="stat-card">
      <div class="stat-num" style="color:${col}">${v}</div>
      <div class="stat-lbl">${l}</div>
    </div>`).join('');

  tbody.innerHTML = components.map(c => {
    const risk   = calcComponentRisk(c);
    const expBdg = c.exported === true  ? '<span class="badge badge-red">yes</span>' :
                   c.exported === false ? '<span class="badge badge-green">no</span>' :
                   '<span class="badge" style="opacity:.5">inferred</span>';
    const tTag   = `<span class="tag ${TYPE_CLS[c.type]||'tg'}">${c.type}</span>`;
    const iStr   = c.actions.slice(0,2).map(a=>`<span class="tag tg">${a.split('.').pop()}</span>`).join('')
                 + (c.actions.length>2?`<span class="tag tg">+${c.actions.length-2}</span>`:'');
    const dStr   = c.schemes.map(s=>`<span class="tag tr">${s}://</span>`).join('');
    return `<tr>
      <td>${tTag}</td>
      <td style="max-width:140px;word-break:break-all;font-size:10px">${c.name.replace(/^.*\./,'')}</td>
      <td>${expBdg}</td>
      <td style="font-size:10px;opacity:.7;max-width:120px;word-break:break-all">${c.perm?c.perm.split('.').pop():'—'}</td>
      <td>${iStr}${dStr}</td>
      <td>${riskDots(risk)}</td>
    </tr>`;
  }).join('');
}

function renderFindings(findings){
  const el = $('findings-body');
  if (!findings.length){
    el.innerHTML = '<div class="empty">No findings detected — looks clean! 🟢</div>';
    return;
  }
  const sevLbl = { critical:'🔴 CRITICAL', high:'🟠 HIGH', medium:'🟡 MEDIUM', low:'🟢 LOW' };
  el.innerHTML = '<div class="flist">' + findings.map(f => `
    <div class="finding ${f.sev}">
      <div class="f-sev">${sevLbl[f.sev]||f.sev}</div>
      <div class="f-title">${f.title}</div>
      <div class="f-body">${f.body}</div>
      <div class="f-fix"><strong>Fix:</strong> ${f.fix}</div>
    </div>`).join('') + '</div>';
}

function renderReport(data){
  const { parsed, findings, score } = data;
  const { components, pkg, permissions, allowBackup, debuggable } = parsed;
  const exp    = components.filter(c => c.inferredExported);
  const noPerm = exp.filter(c => !c.perm);
  const crits  = findings.filter(f => f.sev==='critical');
  const highs  = findings.filter(f => f.sev==='high');
  const meds   = findings.filter(f => f.sev==='medium');

  const scoreBadge = score >= 70 ? 'badge-red' : score >= 40 ? 'badge-amber' : 'badge-green';
  const scoreLabel = score >= 70 ? 'HIGH RISK' : score >= 40 ? 'MEDIUM RISK' : 'LOW RISK';

  $('report-body').innerHTML = `
    <div style="display:flex;flex-direction:column;gap:14px">

      <!-- Score -->
      <div class="report-section" style="display:flex;align-items:center;gap:20px">
        <div>
          <div class="score-big" style="color:${score>=70?'var(--red)':score>=40?'var(--amber)':'var(--green)'}">${score}</div>
          <div style="font-size:10px;color:var(--text3);letter-spacing:.08em;text-transform:uppercase;margin-top:2px">/ 100 risk score</div>
        </div>
        <div style="flex:1">
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
            <span class="badge ${scoreBadge}">${scoreLabel}</span>
            <span class="badge badge-red">${crits.length} critical</span>
            <span class="badge badge-amber">${highs.length} high</span>
            <span class="badge badge-info">${meds.length} medium</span>
          </div>
          <div style="font-size:11px;color:var(--text2);font-family:var(--sans);line-height:1.6">
            Package <strong>${pkg}</strong> — ${components.length} components, ${exp.length} exported, ${noPerm.length} without permission guard.
            ${debuggable ? '⚠️ App is <strong>debuggable</strong>.' : ''}
            ${allowBackup ? '⚠️ ADB <strong>backup enabled</strong>.' : ''}
          </div>
        </div>
      </div>

      <!-- Summary table -->
      <div class="report-section">
        <div class="report-title">Attack Surface Summary</div>
        <table style="width:100%;font-size:11px;border-collapse:collapse">
          <tr style="border-bottom:0.5px solid var(--border)">
            <td style="padding:5px 0;color:var(--text3)">Total components</td>
            <td style="padding:5px 0;text-align:right;font-weight:700">${components.length}</td>
          </tr>
          <tr style="border-bottom:0.5px solid var(--border)">
            <td style="padding:5px 0;color:var(--text3)">Exported components</td>
            <td style="padding:5px 0;text-align:right;font-weight:700;color:var(--red)">${exp.length}</td>
          </tr>
          <tr style="border-bottom:0.5px solid var(--border)">
            <td style="padding:5px 0;color:var(--text3)">Exported without permission</td>
            <td style="padding:5px 0;text-align:right;font-weight:700;color:var(--red)">${noPerm.length}</td>
          </tr>
          <tr style="border-bottom:0.5px solid var(--border)">
            <td style="padding:5px 0;color:var(--text3)">Deep links (schemes)</td>
            <td style="padding:5px 0;text-align:right;font-weight:700">${components.filter(c=>c.schemes.length>0).length}</td>
          </tr>
          <tr style="border-bottom:0.5px solid var(--border)">
            <td style="padding:5px 0;color:var(--text3)">Permissions declared</td>
            <td style="padding:5px 0;text-align:right;font-weight:700">${permissions.length}</td>
          </tr>
          <tr style="border-bottom:0.5px solid var(--border)">
            <td style="padding:5px 0;color:var(--text3)">ADB backup</td>
            <td style="padding:5px 0;text-align:right;font-weight:700;color:${allowBackup?'var(--red)':'var(--green)'}">${allowBackup?'Enabled':'Disabled'}</td>
          </tr>
          <tr>
            <td style="padding:5px 0;color:var(--text3)">Debuggable</td>
            <td style="padding:5px 0;text-align:right;font-weight:700;color:${debuggable?'var(--red)':'var(--green)'}">${debuggable?'YES ⚠️':'No'}</td>
          </tr>
        </table>
      </div>

      <!-- Exported components list -->
      <div class="report-section">
        <div class="report-title">Exported Components (${exp.length})</div>
        <div style="display:flex;flex-direction:column;gap:6px">
          ${exp.map(c => {
            const risk = riskLevel(calcComponentRisk(c));
            const col  = risk==='critical'?'var(--red)':risk==='high'?'var(--amber)':'var(--green)';
            return `<div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:0.5px solid var(--border)">
              <span class="tag ${TYPE_CLS[c.type]||'tg'}" style="flex-shrink:0">${c.type}</span>
              <span style="flex:1;font-size:11px;word-break:break-all">${c.name}</span>
              <span style="font-size:10px;color:${col};font-weight:700;flex-shrink:0;text-transform:uppercase">${risk}</span>
            </div>`;
          }).join('')}
        </div>
      </div>

      <!-- Remediation roadmap -->
      <div class="report-section">
        <div class="report-title">Remediation Roadmap</div>
        <div style="display:flex;flex-direction:column;gap:8px">
          ${findings.slice(0,8).map((f,i) => `
            <div style="display:flex;gap:10px;font-size:11px;font-family:var(--sans)">
              <span style="font-family:var(--mono);font-weight:700;color:var(--text3);flex-shrink:0;min-width:18px">${i+1}.</span>
              <div>
                <div style="font-weight:700;margin-bottom:2px">${f.title}</div>
                <div style="color:var(--green)">${f.fix}</div>
              </div>
            </div>`).join('')}
        </div>
      </div>

    </div>`;
}

// ── Top badges ────────────────────────────────────────────────────────────────

function updateBadges(pkg, score){
  const ab = $('app-badge');
  ab.textContent = pkg; ab.style.display = '';

  const rb = $('risk-badge');
  rb.textContent = `Risk: ${score}/100`;
  rb.className   = 'badge ' + (score>=70?'badge-red':score>=40?'badge-amber':'badge-green');
  rb.style.display = '';
}

// ── Main scan ─────────────────────────────────────────────────────────────────

async function analyzeXML(){
  const xml = $('xml-input').value.trim();
  if (!xml){ alert('No manifest to scan.\nPaste an AndroidManifest.xml or drop an APK first.'); return; }

  setBusy(true);
  setStatus('Scanning…', 'var(--blue)');

  try {
    const parsed   = parseManifest(xml);
    const findings = buildFindings(parsed);
    const score    = computeSurfaceScore({ ...parsed, findings });
    const mermaid  = buildMermaidGraph({ components: parsed.components, pkg: parsed.pkg });

    updateBadges(parsed.pkg, score);
    renderComponents(parsed.components);
    renderFindings(findings);
    buildSVGGraph({ components: parsed.components, pkg: parsed.pkg });
    $('mermaid-box').textContent = mermaid;
    renderReport({ parsed, findings, score });

    setStatus(
      `✓ ${parsed.components.length} components · ${findings.length} findings · risk ${score}/100`,
      'var(--green)'
    );
    switchTab('findings');

  } catch(err) {
    setStatus('Error: ' + err.message, 'var(--red)');
    console.error('[analyzeXML]', err);
  } finally {
    setBusy(false);
  }
}
