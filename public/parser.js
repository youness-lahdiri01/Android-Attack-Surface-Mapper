/**
 * parser.js — AndroidManifest.xml parser
 * Extracts components, permissions, and app-level flags.
 */

const DEMO_MANIFEST = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerablebank"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.CAMERA"/>

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:label="VulnerableBank"
        android:networkSecurityConfig="@xml/network_security_config">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

        <activity android:name=".LoginActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <data android:scheme="bank" android:host="login"/>
            </intent-filter>
        </activity>

        <activity android:name=".TransferActivity" android:exported="true"/>

        <activity android:name=".AdminActivity"
            android:exported="true"
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
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_provider_paths"/>
        </provider>

    </application>
</manifest>`;

/**
 * Extract components of a given type from raw XML string.
 * @param {string} xml
 * @param {string} type  - e.g. "Activity"
 * @param {string} tag   - e.g. "activity"
 * @returns {Array}
 */
function extractComponents(xml, type, tag) {
  const results = [];
  const re = new RegExp(`<${tag}([\\s\\S]*?)(?:/>|>[\\s\\S]*?</${tag}>)`, 'gi');
  let m;
  while ((m = re.exec(xml)) !== null) {
    const block = m[0];
    const attrs = m[1];

    const name        = (attrs.match(/android:name="([^"]+)"/) || [])[1] || '';
    const exportedRaw = attrs.match(/android:exported="(true|false)"/i);
    const exported    = exportedRaw ? exportedRaw[1] === 'true' : null;
    const perm        = (attrs.match(/android:permission="([^"]+)"/) || [])[1] || '';
    const authorities = (attrs.match(/android:authorities="([^"]+)"/) || [])[1] || '';
    const grantUri    = /android:grantUriPermissions="true"/i.test(attrs);
    const taMatch     = attrs.match(/android:taskAffinity="([^"]*)"/);
    const taskAffinity = taMatch ? taMatch[1] : null;

    const actions  = [...block.matchAll(/action android:name="([^"]+)"/gi)].map(x => x[1]);
    const schemes  = [...block.matchAll(/data android:scheme="([^"]+)"/gi)].map(x => x[1]);
    const hosts    = [...block.matchAll(/data android:host="([^"]+)"/gi)].map(x => x[1]);
    const mimeTypes = [...block.matchAll(/data android:mimeType="([^"]+)"/gi)].map(x => x[1]);

    // Infer exported: components with intent-filters are implicitly exported pre-API31
    const inferredExported = exported !== null ? exported : (actions.length > 0);

    results.push({
      type,
      name,
      exported,
      inferredExported,
      perm,
      authorities,
      grantUri,
      taskAffinity,
      actions,
      schemes,
      hosts,
      mimeTypes,
    });
  }
  return results;
}

/**
 * Parse an AndroidManifest.xml string.
 * @param {string} xml
 * @returns {{ components, pkg, permissions, allowBackup, debuggable, networkSecConfig }}
 */
function parseManifest(xml) {
  const pkg              = (xml.match(/package="([^"]+)"/) || [])[1] || 'com.unknown.app';
  const allowBackup      = /allowBackup="true"/i.test(xml);
  const debuggable       = /debuggable="true"/i.test(xml);
  const networkSecConfig = /networkSecurityConfig/i.test(xml);
  const clearTextTraffic = /usesCleartextTraffic="true"/i.test(xml);

  const sdkBlock  = (xml.match(/<uses-sdk\b[^>]*\/?>/i) || [''])[0];
  const targetSdk = parseInt((sdkBlock.match(/android:targetSdkVersion="(\d+)"/) || [])[1]) || 0;
  const minSdk    = parseInt((sdkBlock.match(/android:minSdkVersion="(\d+)"/)    || [])[1]) || 0;

  const permissions = [...xml.matchAll(/uses-permission[^>]+android:name="([^"]+)"/gi)].map(m => m[1]);

  const components = [
    ...extractComponents(xml, 'Activity', 'activity'),
    ...extractComponents(xml, 'Service',  'service'),
    ...extractComponents(xml, 'Receiver', 'receiver'),
    ...extractComponents(xml, 'Provider', 'provider'),
  ];

  return { components, pkg, permissions, allowBackup, debuggable, networkSecConfig, clearTextTraffic, targetSdk, minSdk };
}

/**
 * Calculate a 0-100 risk score for a single component.
 * @param {Object} component
 * @returns {number}
 */
function calcComponentRisk(c) {
  let score = 0;
  if (c.inferredExported)  score += 40;
  if (!c.perm && c.inferredExported) score += 25;
  if (c.actions.length > 0) score += 10;
  if (c.schemes.length > 0) score += 15;
  if (c.type === 'Provider' && c.inferredExported) score += 10;
  return Math.min(score, 100);
}

/**
 * Map numeric score to severity string.
 * @param {number} s
 * @returns {'critical'|'high'|'medium'|'low'}
 */
function riskLevel(s) {
  if (s >= 70) return 'critical';
  if (s >= 40) return 'high';
  if (s >= 20) return 'medium';
  return 'low';
}
