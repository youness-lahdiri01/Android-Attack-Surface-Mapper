export function parseNetworkSecurityConfig(xml) {
  let doc
  try {
    doc = new DOMParser().parseFromString(xml, 'application/xml')
  } catch {
    return null
  }
  if (doc.querySelector('parsererror')) return null

  const getCertSrcs = (el) =>
    el ? [...el.querySelectorAll('certificates')].map(c => c.getAttribute('src')).filter(Boolean) : []

  const baseConfig = doc.querySelector('base-config')
  const debugOverrides = doc.querySelector('debug-overrides')

  return {
    baseConfig: baseConfig ? {
      cleartextPermitted: baseConfig.getAttribute('cleartextTrafficPermitted') === 'true',
      certSources: getCertSrcs(baseConfig),
    } : null,
    domainConfigs: [...doc.querySelectorAll('domain-config')].map(dc => ({
      domains: [...dc.querySelectorAll('domain')].map(d => d.textContent.trim()).filter(Boolean),
      cleartextPermitted: dc.getAttribute('cleartextTrafficPermitted') === 'true',
      certSources: getCertSrcs(dc),
      pinSets: [...dc.querySelectorAll('pin-set')].map(ps => ({
        expiration: ps.getAttribute('expiration'),
        pinCount: ps.querySelectorAll('pin').length,
      })),
    })),
    debugOverrides: debugOverrides ? {
      certSources: getCertSrcs(debugOverrides),
    } : null,
  }
}

export function buildNetSecFindings(netSec) {
  if (!netSec) return []
  const findings = []

  if (netSec.baseConfig?.cleartextPermitted) {
    findings.push({
      sev: 'high',
      title: 'Network Security Config permits cleartext traffic globally',
      body: '<base-config cleartextTrafficPermitted="true"> allows unencrypted HTTP for every domain. On API 28+, the platform default is false — this flag actively downgrades security for the entire app.',
      fix: 'Remove cleartextTrafficPermitted="true" from <base-config> and migrate all endpoints to HTTPS. If a legacy endpoint strictly requires HTTP, scope it to a <domain-config> for that domain only.',
    })
  }

  if (netSec.baseConfig?.certSources.includes('user')) {
    findings.push({
      sev: 'high',
      title: 'Network Security Config trusts user-installed CA certificates',
      body: '<certificates src="user"/> in <base-config> makes the app trust any CA installed by the device user for all connections. An attacker who tricks the user into installing a rogue CA can silently intercept all HTTPS traffic.',
      fix: 'Remove <certificates src="user"/> from <base-config>. If required for internal testing, restrict it to <debug-overrides> so it only applies to debug builds.',
    })
  }

  const cleartextDomains = netSec.domainConfigs.filter(d => d.cleartextPermitted)
  if (cleartextDomains.length > 0) {
    const list = cleartextDomains.flatMap(d => d.domains).join(', ') || `${cleartextDomains.length} domain(s)`
    findings.push({
      sev: 'medium',
      title: `Cleartext HTTP permitted for: ${list}`,
      body: `cleartextTrafficPermitted="true" is scoped to: ${list}. HTTP traffic to these hosts is unencrypted and susceptible to MITM on untrusted networks.`,
      fix: 'Migrate these endpoints to HTTPS and remove cleartextTrafficPermitted="true". If controlled by a third-party SDK, request an HTTPS endpoint from the vendor.',
    })
  }

  const userCertDomains = netSec.domainConfigs.filter(d => d.certSources.includes('user'))
  if (userCertDomains.length > 0) {
    const list = userCertDomains.flatMap(d => d.domains).join(', ') || `${userCertDomains.length} domain(s)`
    findings.push({
      sev: 'medium',
      title: `User CA certificates trusted for domain(s): ${list}`,
      body: `<certificates src="user"/> is scoped to ${list}. Although limited in scope, a user with physical access can still install a CA and intercept traffic to these specific hosts.`,
      fix: 'Restrict this to <debug-overrides> for dev builds only. In production, trust only system CAs and consider adding certificate pinning for sensitive domains.',
    })
  }

  const today = new Date()
  netSec.domainConfigs.forEach(dc => {
    dc.pinSets.forEach(ps => {
      if (!ps.expiration) return
      const expDate = new Date(ps.expiration)
      if (!isNaN(expDate) && expDate < today) {
        const list = dc.domains.join(', ') || 'unknown domain'
        findings.push({
          sev: 'medium',
          title: `Expired certificate pin for: ${list}`,
          body: `The pin-set for [${list}] expired on ${ps.expiration}. Expired pins either break all connections to that domain (connection failure) or silently stop enforcing pinning depending on the failsafe setting.`,
          fix: 'Rotate the pinned certificate, update the SHA-256 digest in the pin-set, and extend the expiration date. Always include a backup pin to prevent lockout during rotation.',
        })
      }
    })
  })

  return findings
}
