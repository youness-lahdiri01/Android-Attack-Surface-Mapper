/**
 * apk.js — APK loader v2
 * Opens APK as ZIP, extracts + decodes binary AndroidManifest.xml
 * No server needed — 100% browser-side.
 */
const APKLoader = (() => {

  const JSZIP_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
  let _loaded = false;

  function loadJSZip() {
    return new Promise((resolve, reject) => {
      if (typeof JSZip !== 'undefined') { resolve(); return; }
      if (_loaded) { resolve(); return; }
      const s = document.createElement('script');
      s.src = JSZIP_CDN;
      s.onload  = () => { _loaded = true; resolve(); };
      s.onerror = () => reject(new Error('Cannot load JSZip from CDN. Check internet connection.'));
      document.head.appendChild(s);
    });
  }

  function readAsBuffer(file) {
    return new Promise((res, rej) => {
      const r = new FileReader();
      r.onload  = e => res(e.target.result);
      r.onerror = () => rej(new Error('Cannot read file'));
      r.readAsArrayBuffer(file);
    });
  }

  async function load(file, onProgress) {
    const prog = onProgress || (() => {});

    prog('Loading JSZip library…');
    await loadJSZip();

    prog(`Reading ${file.name}…`);
    const buffer = await readAsBuffer(file);

    prog('Opening APK archive…');
    let zip;
    try {
      zip = await JSZip.loadAsync(buffer);
    } catch(e) {
      throw new Error('Cannot open as ZIP: ' + e.message + '. Is this a valid APK?');
    }

    // Collect APK metadata
    const allFiles     = Object.keys(zip.files);
    const dexFiles     = allFiles.filter(f => /^classes\d*\.dex$/.test(f));
    const nativeLibs   = allFiles.filter(f => f.startsWith('lib/') && f.endsWith('.so'));
    const permissions  = [];    // will be filled after manifest parse
    const hasAssets    = allFiles.some(f => f.startsWith('assets/'));
    const hasResources = zip.file('resources.arsc') !== null;

    prog('Extracting AndroidManifest.xml…');
    const manifestFile = zip.file('AndroidManifest.xml');
    if (!manifestFile) {
      throw new Error('AndroidManifest.xml missing from APK. This may be a split APK or corrupt file.');
    }

    prog('Reading binary manifest…');
    const manifestBytes = await manifestFile.async('uint8array');

    // Debug: log first bytes
    console.log('[APKLoader] Manifest first 16 bytes:', Array.from(manifestBytes.slice(0, 16)).map(b => '0x' + b.toString(16).padStart(2,'0')).join(' '));
    console.log('[APKLoader] Manifest size:', manifestBytes.byteLength, 'bytes');

    prog('Decoding AXML binary format…');
    let xml;
    try {
      xml = AXML.parse(manifestBytes);
    } catch(e) {
      console.error('[APKLoader] AXML parse error:', e);
      throw new Error('Failed to decode manifest: ' + e.message);
    }

    console.log('[APKLoader] Decoded XML preview:\n', xml.substring(0, 500));

    // Lib architectures
    const archs = [...new Set(nativeLibs.map(f => f.split('/')[1]).filter(Boolean))];

    const apkInfo = {
      fileName   : file.name,
      fileSize   : (file.size / 1024 / 1024).toFixed(2) + ' MB',
      dexCount   : dexFiles.length,
      nativeArchs: archs.length ? archs.join(', ') : 'none',
      hasAssets,
      hasResources,
      totalFiles : allFiles.length,
    };

    prog('Done!');
    return { xml, apkInfo };
  }

  return { load };
})();
