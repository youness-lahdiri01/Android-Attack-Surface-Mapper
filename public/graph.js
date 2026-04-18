/**
 * graph.js — SVG graph + Mermaid diagram builder
 */

const TYPE_COLORS = {
  Activity: { fill: '#042C53', stroke: '#185FA5', text: '#B5D4F4' },
  Service:  { fill: '#04342C', stroke: '#0F6E56', text: '#9FE1CB' },
  Receiver: { fill: '#4A1B0C', stroke: '#993C1D', text: '#F5C4B3' },
  Provider: { fill: '#412402', stroke: '#854F0B', text: '#FAC775' },
};

/**
 * Render an SVG attack graph inside #graph-svg.
 * @param {{ components: Array, pkg: string }} data
 */
function buildSVGGraph(data) {
  const { components, pkg } = data;
  const svg = document.getElementById('graph-svg');
  svg.innerHTML = '';

  const exported = components.filter(c => c.inferredExported);
  if (!exported.length) {
    svg.innerHTML = '<text x="330" y="155" text-anchor="middle" style="fill:#888;font-size:12px;font-family:monospace">No exported components found</text>';
    return;
  }

  const W = 660;
  const cols = Math.min(exported.length, 4);
  const nodeW = 130, nodeH = 40, gapX = 16;
  const totalW = cols * nodeW + (cols - 1) * gapX;
  const startX = (W - totalW) / 2;
  const startY = 80;
  const pkgX = W / 2, pkgY = 28;

  // Arrow marker
  const defs = `<defs>
    <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
      <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
  </defs>`;

  let svgContent = defs;

  // App pill
  svgContent += `
    <rect x="${pkgX - 55}" y="${pkgY - 13}" width="110" height="26" rx="5"
      fill="#2C2C2A" stroke="#888780" stroke-width="0.5"/>
    <text x="${pkgX}" y="${pkgY + 4}" text-anchor="middle"
      fill="#D3D1C7" font-size="11" font-weight="600" font-family="monospace">
      ${(pkg.split('.').pop() || 'App').substring(0, 14)}
    </text>`;

  let maxY = startY + nodeH + 40;

  exported.forEach((c, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const cx = startX + col * (nodeW + gapX) + nodeW / 2;
    const cy = startY + row * (nodeH + 50) + nodeH / 2;
    const colors = TYPE_COLORS[c.type] || TYPE_COLORS.Activity;
    const bottomY = cy + nodeH / 2;
    maxY = Math.max(maxY, bottomY + 30);

    // Connector from App → component
    svgContent += `
      <line x1="${pkgX}" y1="${pkgY + 13}" x2="${cx}" y2="${cy - nodeH / 2}"
        stroke="${colors.stroke}" stroke-width="0.7" opacity="0.55"
        marker-end="url(#arr)"/>`;

    // Permission indicator dot
    const dotColor = c.perm ? '#639922' : (c.inferredExported ? '#E24B4A' : '#888');
    svgContent += `
      <circle cx="${cx + nodeW / 2 - 7}" cy="${cy - nodeH / 2 + 7}" r="5"
        fill="${dotColor}" stroke="none"/>`;

    // Component rect
    svgContent += `
      <rect x="${cx - nodeW / 2}" y="${cy - nodeH / 2}" width="${nodeW}" height="${nodeH}" rx="6"
        fill="${colors.fill}" stroke="${colors.stroke}" stroke-width="0.5"/>
      <text x="${cx}" y="${cy - 8}" text-anchor="middle"
        fill="${colors.text}" font-size="9" font-weight="600" font-family="monospace" opacity="0.65">
        ${c.type.toUpperCase()}
      </text>
      <text x="${cx}" y="${cy + 8}" text-anchor="middle"
        fill="${colors.text}" font-size="11" font-weight="600" font-family="monospace">
        ${c.name.replace(/^.*\./, '').substring(0, 15)}
      </text>`;

    // Deep link nodes
    c.schemes.slice(0, 2).forEach((s, j) => {
      const dy = bottomY + 22 + j * 18;
      maxY = Math.max(maxY, dy + 10);
      svgContent += `
        <line x1="${cx}" y1="${bottomY}" x2="${cx}" y2="${dy - 6}"
          stroke="#993556" stroke-width="0.5" stroke-dasharray="3 2" marker-end="url(#arr)"/>
        <text x="${cx}" y="${dy}" text-anchor="middle"
          fill="#ED93B1" font-size="9" font-family="monospace">${s}://</text>`;
    });
  });

  svg.setAttribute('viewBox', `0 0 ${W} ${maxY + 16}`);
  svg.innerHTML = svgContent;
}

/**
 * Generate a Mermaid LR diagram string.
 * @param {{ components: Array, pkg: string }} data
 * @returns {string}
 */
function buildMermaidGraph(data) {
  const { components, pkg } = data;
  const appId = 'APP';
  const shortPkg = pkg.split('.').pop() || 'App';
  const lines = [
    'graph LR',
    `  ${appId}["${shortPkg}"]:::app`,
  ];

  const exported = components.filter(c => c.inferredExported);

  exported.forEach((c, i) => {
    const short = c.name.replace(/^.*\./, '');
    const id = `C${i}`;
    const typePrefix = c.type[0];
    lines.push(`  ${id}["${typePrefix}: ${short}"]:::${c.type.toLowerCase()}`);
    lines.push(`  ${appId} --> ${id}`);

    if (c.perm) {
      const pid = `P${i}`;
      lines.push(`  ${pid}(["${c.perm.split('.').pop()}"]):::perm`);
      lines.push(`  ${pid} -. guards .-> ${id}`);
    }

    c.actions
      .filter(a => !a.includes('android.intent.action.MAIN'))
      .slice(0, 3)
      .forEach((a, j) => {
        const aid = `A${i}_${j}`;
        const aShort = a.split('.').pop();
        lines.push(`  ${aid}>"${aShort}"]:::intent`);
        lines.push(`  ${aid} --> ${id}`);
      });

    c.schemes.slice(0, 2).forEach((s, j) => {
      const sid = `S${i}_${j}`;
      lines.push(`  ${sid}[/"${s}://..."/]:::deeplink`);
      lines.push(`  ${sid} --> ${id}`);
    });
  });

  lines.push('');
  lines.push('  classDef app      fill:#2C2C2A,color:#D3D1C7,stroke:#888780');
  lines.push('  classDef activity fill:#042C53,color:#B5D4F4,stroke:#185FA5');
  lines.push('  classDef service  fill:#04342C,color:#9FE1CB,stroke:#0F6E56');
  lines.push('  classDef receiver fill:#4A1B0C,color:#F5C4B3,stroke:#993C1D');
  lines.push('  classDef provider fill:#412402,color:#FAC775,stroke:#854F0B');
  lines.push('  classDef perm     fill:#26215C,color:#CECBF6,stroke:#534AB7');
  lines.push('  classDef intent   fill:#173404,color:#C0DD97,stroke:#3B6D11');
  lines.push('  classDef deeplink fill:#4B1528,color:#F4C0D1,stroke:#993556');

  return lines.join('\n');
}
