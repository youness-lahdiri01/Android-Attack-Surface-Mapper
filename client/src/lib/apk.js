import JSZip from 'jszip'
import { parseAXML } from './axml.js'

export async function loadAPK(file, onProgress = () => {}) {
  onProgress('Reading file…')
  const buffer = await file.arrayBuffer()

  onProgress('Opening APK archive…')
  let zip
  try {
    zip = await JSZip.loadAsync(buffer)
  } catch (e) {
    throw new Error('Cannot open as ZIP: ' + e.message + '. Is this a valid APK?')
  }

  const allFiles   = Object.keys(zip.files)
  const dexFiles   = allFiles.filter(f => /^classes\d*\.dex$/.test(f))
  const nativeLibs = allFiles.filter(f => f.startsWith('lib/') && f.endsWith('.so'))

  onProgress('Extracting AndroidManifest.xml…')
  const manifestFile = zip.file('AndroidManifest.xml')
  if (!manifestFile)
    throw new Error('AndroidManifest.xml missing from APK. This may be a split APK or corrupt file.')

  onProgress('Decoding binary manifest…')
  const manifestBytes = await manifestFile.async('uint8array')

  let xml
  try {
    xml = parseAXML(manifestBytes)
  } catch (e) {
    throw new Error('Failed to decode manifest: ' + e.message)
  }

  const archs = [...new Set(nativeLibs.map(f => f.split('/')[1]).filter(Boolean))]

  const apkInfo = {
    fileName:    file.name,
    fileSize:    (file.size / 1024 / 1024).toFixed(2) + ' MB',
    dexCount:    dexFiles.length,
    nativeArchs: archs.length ? archs.join(', ') : 'none',
    hasAssets:   allFiles.some(f => f.startsWith('assets/')),
    hasResources: zip.file('resources.arsc') !== null,
    totalFiles:  allFiles.length,
  }

  return { xml, apkInfo }
}
