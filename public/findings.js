/**
 * findings.js — Security pattern detection engine
 */

const SENSITIVE_NAME_PATTERNS = [
  /transfer/i, /payment/i, /admin/i, /root/i, /internal/i,
  /secret/i, /private/i, /wallet/i, /banking/i, /auth/i,
];

const DANGEROUS_PERMISSIONS = [
  'android.permission.READ_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.SEND_SMS',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_CONTACTS',
  'android.permission.READ_CALL_LOG',
  'android.permission.PROCESS_OUTGOING_CALLS',
  'android.permission.CAMERA',
  'android.permission.RECORD_AUDIO',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.READ_EXTERNAL_STORAGE',
  'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.GET_ACCOUNTS',
  'android.permission.USE_BIOMETRIC',
  'android.permission.USE_FINGERPRINT',
];

/**
 * Run all security checks and return a list of findings.
 */
function buildFindings(data) {
  const { components, allowBackup, debuggable, permissions, pkg, clearTextTraffic, targetSdk = 0 } = data;
  const findings = [];

  // ── App-level checks ──────────────────────────────────────────────────────

  if (debuggable) {
    findings.push({
      sev: 'critical',
      title: 'Application is debuggable in production',
      body: 'android:debuggable="true" allows ADB debugging on any device, even non-rooted ones. '
          + 'Attackers can dump heap memory, inspect runtime variables, set breakpoints, '
          + 'and extract secrets from memory.',
      fix: 'Remove android:debuggable="true". Gradle release builds set it to false automatically. '
         + 'Never ship this flag in production.',
    });
  }

  if (allowBackup) {
    findings.push({
      sev: 'high',
      title: 'ADB backup is enabled',
      body: 'android:allowBackup="true" allows ADB (adb backup) to extract the app\'s private data '
          + 'directory without root. Tokens, databases, and session files can be exfiltrated on any '
          + 'unlocked device.',
      fix: 'Set android:allowBackup="false", or define android:fullBackupContent with explicit '
         + 'exclusion rules for sensitive files (tokens, SharedPreferences, databases).',
    });
  }

  if (clearTextTraffic) {
    findings.push({
      sev: 'high',
      title: 'Cleartext HTTP traffic allowed',
      body: 'android:usesCleartextTraffic="true" permits unencrypted HTTP. '
          + 'Credentials and session tokens may be intercepted on untrusted networks (MITM).',
      fix: 'Remove this flag and enforce HTTPS everywhere. Use a Network Security Config '
         + '(<network-security-config>) to pin certificates for sensitive endpoints.',
    });
  }

  if (targetSdk > 0 && targetSdk < 31) {
    const sev = targetSdk < 23 ? 'high' : 'medium';
    findings.push({
      sev,
      title: `Low targetSdkVersion: API ${targetSdk}`,
      body: `Targeting API ${targetSdk} means the app misses mandatory security improvements: `
          + (targetSdk < 23 ? 'runtime permissions (users cannot deny dangerous perms individually), ' : '')
          + (targetSdk < 26 ? 'background execution limits, ' : '')
          + (targetSdk < 28 ? 'cleartext blocked by default, ' : '')
          + 'explicit android:exported requirement (API 31+). '
          + 'Google Play may restrict distribution for apps targeting below API 33.',
      fix: 'Raise targetSdkVersion to at least 33 (Android 13) and fix all resulting compatibility issues.',
    });
  }

  // ── Component-level checks ────────────────────────────────────────────────

  const exported = components.filter(c => c.inferredExported);

  exported.forEach(c => {
    const isSensitive = SENSITIVE_NAME_PATTERNS.some(p => p.test(c.name));

    if (!c.perm) {
      const sev = isSensitive ? 'critical' : 'high';
      findings.push({
        sev,
        title: `${c.type} exported without permission guard: ${c.name.replace(/^.*\./, '')}`,
        body: `"${c.name}" is accessible to any app on the device. `
            + (isSensitive
               ? 'The name suggests it handles sensitive operations. Any malicious app can invoke it directly.'
               : 'Without a permission, a third-party app can send arbitrary intents to this component.'),
        fix: 'Add android:permission="your.app.permission.CUSTOM" with protectionLevel="signature", '
           + 'or set android:exported="false" if external access is not required.',
      });
    }

    // ContentProvider without read/write permissions (separate finding — distinct risk)
    if (c.type === 'Provider' && !c.perm) {
      findings.push({
        sev: 'critical',
        title: `ContentProvider exposed without read/writePermission: ${c.name.replace(/^.*\./, '')}`,
        body: `"${c.name}" exposes its data to all apps with no access control. `
            + 'ContentProviders can leak entire SQLite databases, files, and account data.',
        fix: 'Add android:readPermission and android:writePermission. '
           + 'For file sharing, replace with FileProvider (exported="false") and use grantUriPermissions.',
      });
    }
  });

  // Deep links without autoVerify
  components.filter(c => c.schemes.length > 0).forEach(c => {
    const hasHttp = c.schemes.some(s => s === 'http' || s === 'https');
    findings.push({
      sev: hasHttp ? 'high' : 'medium',
      title: `Deep link without App Link verification: ${c.name.replace(/^.*\./, '')}`,
      body: `"${c.name}" handles scheme(s) [${c.schemes.join(', ')}] without android:autoVerify="true". `
          + 'Any installed app can declare the same intent-filter and intercept these links (URL hijacking).',
      fix: 'Add android:autoVerify="true" to the intent-filter and publish a valid '
         + 'Digital Asset Links file at https://yourdomain.com/.well-known/assetlinks.json.',
    });
  });

  // Dangerous permissions
  const dangerousRequested = permissions.filter(p => DANGEROUS_PERMISSIONS.includes(p));
  if (dangerousRequested.length > 0) {
    findings.push({
      sev: 'medium',
      title: 'Overprivileged: dangerous permissions declared',
      body: `The app requests ${dangerousRequested.length} dangerous permission(s): `
          + dangerousRequested.map(p => p.split('.').pop()).join(', ') + '. '
          + 'Each increases the blast radius of a compromise.',
      fix: 'Apply the principle of least privilege. Remove permissions not strictly required. '
         + 'Request remaining permissions lazily (only when first needed), not at startup.',
    });
  }

  // Implicit export via intent-filter (legacy behavior, pre-API 31)
  const implicitExport = components.filter(c => c.exported === null && c.actions.length > 0);
  if (implicitExport.length > 0) {
    findings.push({
      sev: 'medium',
      title: `${implicitExport.length} component(s) implicitly exported via intent-filter`,
      body: 'Components with intent-filters and no explicit android:exported attribute are '
          + 'implicitly exported on API < 31. On API 31+ this causes an install error. '
          + 'Affected: ' + implicitExport.map(c => c.name.replace(/^.*\./, '')).join(', ') + '.',
      fix: 'Add android:exported="true" or "false" explicitly to every component that has an intent-filter. '
         + 'This is mandatory for targetSdkVersion 31+.',
    });
  }

  // Task affinity hijacking
  components
    .filter(c => c.type === 'Activity' && c.taskAffinity !== null && c.taskAffinity !== '' && c.inferredExported)
    .forEach(c => {
      findings.push({
        sev: 'medium',
        title: `Custom taskAffinity on exported Activity: ${c.name.replace(/^.*\./, '')}`,
        body: `"${c.name}" sets android:taskAffinity="${c.taskAffinity}". Combined with allowTaskReparenting `
            + 'or a singleTask/singleInstance launchMode, this enables task hijacking — a malicious app '
            + 'can capture this activity into its own task stack.',
        fix: 'Remove android:taskAffinity or set it to an empty string ("") to prevent task reparenting. '
           + 'Audit android:launchMode and android:allowTaskReparenting on the same activity.',
      });
    });

  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.sev] - order[b.sev]);
  return findings;
}

/**
 * Compute an overall surface risk score (0–100).
 * Each finding type carries a weight; app-level flags add a flat penalty.
 */
function computeSurfaceScore(data) {
  const { findings, debuggable, allowBackup, clearTextTraffic } = data;
  let risk = 0;
  if (debuggable)       risk += 25;
  if (allowBackup)      risk += 12;
  if (clearTextTraffic) risk += 10;
  const w = { critical: 12, high: 7, medium: 3, low: 1 };
  findings.forEach(f => { risk += w[f.sev] || 0; });
  return Math.min(100, risk);
}
