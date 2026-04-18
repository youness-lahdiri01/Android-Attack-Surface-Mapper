/**
 * axml.js — Android Binary XML parser v6 — AOSP-correct layout
 *
 * REAL chunk layout for RES_XML_START_ELEMENT:
 *   [chunk header]  8 bytes: type(u16) headerSize(u16) chunkSize(u32)
 *   [ResXMLTree_node] 8 bytes: lineNumber(u32) comment(i32)
 *   [ResXMLTree_attrExt] 20 bytes:
 *       ns(i32+4) name(u32+8) attrStart(u16+12) attrSize(u16+14)
 *       attrCount(u16+16) idAttr(u16+18) classAttr(u16+20) styleAttr(u16+22)
 *   [attrs] each attrSize bytes (usually 20):
 *       ns(i32) name(u32) rawValue(i32) size(u16) res0(u8) dataType(u8) data(u32)
 *
 * Absolute positions from chunk start (pos):
 *   node.lineNumber  = pos + 8
 *   node.comment     = pos + 12
 *   ext.ns           = pos + 16
 *   ext.name         = pos + 20
 *   ext.attrStart    = pos + 24   (relative to ext start = pos+16)
 *   ext.attrSize     = pos + 26
 *   ext.attrCount    = pos + 28
 *   first attr       = pos + 16 + attrStart
 *
 * RES_XML_END_ELEMENT:
 *   [chunk header] 8 bytes
 *   [ResXMLTree_node] 8 bytes: lineNumber(u32) comment(i32)
 *   [ResXMLTree_endElementExt]:
 *       ns(i32) = pos+16
 *       name(u32) = pos+20
 *
 * RES_XML_START_NAMESPACE / END_NAMESPACE:
 *   [chunk header] 8 bytes
 *   [ResXMLTree_node] 8 bytes
 *   [ResXMLTree_namespaceExt]:
 *       prefix(u32) = pos+16
 *       uri(u32)    = pos+20
 */
const AXML = (() => {
  const RES_STRING_POOL_TYPE    = 0x0001;
  const RES_XML_START_NAMESPACE = 0x0100;
  const RES_XML_END_NAMESPACE   = 0x0101;
  const RES_XML_START_ELEMENT   = 0x0102;
  const RES_XML_END_ELEMENT     = 0x0103;
  const RES_XML_CDATA           = 0x0104;

  const TYPE_STRING   = 0x03;
  const TYPE_INT_BOOL = 0x12;
  const TYPE_INT_HEX  = 0x11;
  const TYPE_INT_DEC  = 0x10;
  const TYPE_FLOAT    = 0x04;
  const TYPE_REF      = 0x01;

  function esc(s){
    return String(s)
      .replace(/&/g,'&amp;').replace(/"/g,'&quot;')
      .replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  /* ── String pool ── */
  function readStringPool(dv, base){
    const stringCount  = dv.getUint32(base+8,  true);
    const flags        = dv.getUint32(base+16, true);
    const stringsStart = dv.getUint32(base+20, true);
    const isUtf8       = (flags & 0x100) !== 0;
    const offBase      = base + 28;
    const strBase      = base + stringsStart;
    const strings      = [];
    for(let i = 0; i < stringCount; i++){
      const off = strBase + dv.getUint32(offBase + i*4, true);
      try { strings.push(isUtf8 ? readUtf8(dv, off) : readUtf16(dv, off)); }
      catch(e){ strings.push(''); }
    }
    return strings;
  }

  function readUtf8(dv, off){
    let p = off;
    if(dv.getUint8(p) & 0x80) p += 2; else p += 1;
    let byteLen = dv.getUint8(p++);
    if(byteLen & 0x80){ byteLen = ((byteLen & 0x7f) << 8) | dv.getUint8(p++); }
    return new TextDecoder('utf-8').decode(
      new Uint8Array(dv.buffer, dv.byteOffset + p, byteLen)
    );
  }

  function readUtf16(dv, off){
    let charLen = dv.getUint16(off, true);
    if(charLen & 0x8000){
      charLen = ((charLen & 0x7fff) << 16) | dv.getUint16(off+2, true);
      off += 4;
    } else {
      off += 2;
    }
    return new TextDecoder('utf-16le').decode(
      new Uint8Array(dv.buffer, dv.byteOffset + off, charLen * 2)
    );
  }

  function safeStr(strings, idx, fallback){
    return (idx >= 0 && idx < strings.length) ? strings[idx] : fallback;
  }

  /* ── Value formatter ── */
  function fmtValue(dataType, data, strings){
    switch(dataType){
      case TYPE_STRING:   return safeStr(strings, data, '');
      case TYPE_INT_BOOL: return data ? 'true' : 'false';
      case TYPE_INT_HEX:  return '0x' + (data >>> 0).toString(16);
      case TYPE_INT_DEC:  return String(data | 0);
      case TYPE_REF:      return '@0x' + (data >>> 0).toString(16).padStart(8,'0');
      case TYPE_FLOAT: {
        const b = new ArrayBuffer(4);
        new DataView(b).setInt32(0, data, true);
        return String(new DataView(b).getFloat32(0, true));
      }
      default: return data !== 0 ? '0x' + (data >>> 0).toString(16) : '';
    }
  }

  /* ── Main parser ── */
  function parse(uint8){
    if(uint8 instanceof ArrayBuffer) uint8 = new Uint8Array(uint8);
    const dv  = new DataView(uint8.buffer, uint8.byteOffset, uint8.byteLength);
    const len = uint8.byteLength;

    const magic = dv.getUint16(0, true);
    if(magic !== 0x0003)
      throw new Error(`Not Android binary XML (magic=0x${magic.toString(16)})`);

    // Skip file header — size in bytes 2-3 (typically 8)
    let pos = dv.getUint16(2, true);

    let strings  = [];
    const nsMap  = {};
    const lines  = ['<?xml version="1.0" encoding="utf-8"?>'];
    let depth    = 0;
    let rootDone = false;

    while(pos + 8 <= len){
      const chunkType = dv.getUint16(pos,   true);
      const chunkSize = dv.getUint32(pos+4, true);
      if(chunkSize === 0 || pos + chunkSize > len) break;

      switch(chunkType){

        case RES_STRING_POOL_TYPE:
          strings = readStringPool(dv, pos);
          break;

        case RES_XML_START_NAMESPACE:
        case RES_XML_END_NAMESPACE: {
          // ResXMLTree_namespaceExt: prefix(u32)@+16, uri(u32)@+20
          if(chunkType === RES_XML_START_NAMESPACE){
            const prefix = safeStr(strings, dv.getUint32(pos+16, true), '');
            const uri    = safeStr(strings, dv.getUint32(pos+20, true), '');
            if(uri && prefix) nsMap[uri] = prefix;
          }
          break;
        }

        case RES_XML_START_ELEMENT: {
          // ResXMLTree_attrExt: ns@+16, name@+20, attrStart@+24, attrSize@+26, attrCount@+28
          const nsIdx    = dv.getInt32 (pos+16, true);
          const nameIdx  = dv.getUint32(pos+20, true);
          const attrStart= dv.getUint16(pos+24, true);
          const attrSize = dv.getUint16(pos+26, true);
          const attrCount= dv.getUint16(pos+28, true);

          const tagName = safeStr(strings, nameIdx, `tag${nameIdx}`);
          const indent  = '  '.repeat(depth);
          let tag       = `${indent}<${tagName}`;

          if(!rootDone){
            rootDone = true;
            for(const [uri, pfx] of Object.entries(nsMap))
              tag += ` xmlns:${pfx}="${esc(uri)}"`;
          }

          // attrs: pos+16 (ext start) + attrStart
          const attrBase = pos + 16 + attrStart;
          for(let i = 0; i < attrCount; i++){
            const a = attrBase + i * attrSize;
            if(a + attrSize > len) break;
            const attrNsIdx = dv.getInt32 (a,    true);
            const attrNmIdx = dv.getUint32(a+4,  true);
            // a+8 = rawValue string idx
            const vType     = dv.getUint8 (a+15);
            const vData     = dv.getUint32(a+16, true);

            const attrName = safeStr(strings, attrNmIdx, `attr${attrNmIdx}`);
            let pfx = '';
            if(attrNsIdx >= 0){
              const nsUri = safeStr(strings, attrNsIdx, '');
              if(nsUri && nsMap[nsUri]) pfx = nsMap[nsUri] + ':';
            }
            const val = fmtValue(vType, vData, strings);
            tag += ` ${pfx}${attrName}="${esc(val)}"`;
          }
          tag += '>';
          lines.push(tag);
          depth++;
          break;
        }

        case RES_XML_END_ELEMENT: {
          depth = Math.max(0, depth - 1);
          // ResXMLTree_endElementExt: ns@+16, name@+20
          const nameIdx = dv.getUint32(pos+20, true);
          lines.push(`${'  '.repeat(depth)}</${safeStr(strings, nameIdx, '?')}>`);
          break;
        }

        case RES_XML_CDATA: {
          const idx  = dv.getUint32(pos+16, true);
          const text = safeStr(strings, idx, '').trim();
          if(text) lines.push('  '.repeat(depth) + esc(text));
          break;
        }
      }
      pos += chunkSize;
    }

    if(lines.length < 2)
      throw new Error('Manifest parsed empty — APK may be encrypted or a split APK.');
    return lines.join('\n');
  }

  return { parse };
})();
