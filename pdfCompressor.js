/**
 * PDF Compressor — targets an output size WINDOW (default 51–55 KB) for any input.
 *
 * How it works:
 *  1. Recompress image XObjects only (Flate RGB -> JPEG, JPEG -> re-optimized JPEG).
 *     Text/fonts/barcodes are NEVER touched, so server-side data extraction keeps working.
 *  2. A quality knob t (0..1) controls scale + JPEG quality of the images.
 *     Binary search finds the t whose output lands inside [MIN, MAX] KB.
 *  3. If even MAX quality gives a file below MIN, an unused padding stream lifts it above
 *     the floor. Padding is invisible: it does not affect pages, text or images.
 *  4. If even MIN quality can't get under MAX (extremely image-heavy PDF), the smallest
 *     achievable file is returned instead — the file is never dropped.
 *
 * Exports:
 *   compressPdfBytes(inputBytes, opts?) -> Uint8Array          (in-memory, used by the server)
 *   compressPdfFile(inputPath, outputPath, opts?) -> number    (CLI helper)
 *
 * CLI:
 *   node pdfCompressor.js input.pdf  output.pdf
 *   node pdfCompressor.js ./uploads  ./compressed     (all PDFs in folder)
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const sharp = require('sharp');
const { PDFDocument, PDFName, PDFRawStream, PDFNumber } = require('pdf-lib');

// ---------------- default target window ----------------
const DEFAULT_MIN_KB = 51;
const DEFAULT_MAX_KB = 55;

// knob t (0..1) -> concrete image settings
function settingsFor(t) {
  return {
    scaleFlate: 0.25 + 0.75 * t,          // 0.25 .. 1.0
    qFlate: Math.round(40 + 55 * t),      // 40 .. 95
    grayFlate: t < 0.85,                  // keep color only near max quality
    scaleJpeg: 0.35 + 0.65 * t,           // 0.35 .. 1.0
    qJpeg: Math.round(40 + 55 * t),       // 40 .. 95
  };
}

function getFilterNames(dict) {
  const filter = dict.get(PDFName.of('Filter'));
  if (!filter) return [];
  if (filter instanceof PDFName) return [filter.toString()];
  if (filter.asArray) return filter.asArray().map(f => f.toString());
  return [filter.toString()];
}

// Undo PNG row predictors (filter byte per row) -> raw RGB pixels
function unfilterPNG(data, width, height, channels) {
  const rowLen = width * channels;
  const out = Buffer.alloc(rowLen * height);
  let inPos = 0;
  for (let y = 0; y < height; y++) {
    const filter = data[inPos++];
    const row = out.subarray(y * rowLen, (y + 1) * rowLen);
    const prev = y > 0 ? out.subarray((y - 1) * rowLen, y * rowLen) : null;
    for (let x = 0; x < rowLen; x++) {
      const raw = data[inPos + x];
      const a = x >= channels ? row[x - channels] : 0;         // left
      const b = prev ? prev[x] : 0;                             // up
      const c = (prev && x >= channels) ? prev[x - channels] : 0; // up-left
      let v;
      switch (filter) {
        case 0: v = raw; break;
        case 1: v = raw + a; break;
        case 2: v = raw + b; break;
        case 3: v = raw + ((a + b) >> 1); break;
        case 4: { // Paeth
          const p = a + b - c;
          const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
          v = raw + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c);
          break;
        }
        default: return null; // unknown filter — bail out safely
      }
      row[x] = v & 0xff;
    }
    inPos += rowLen;
  }
  return out;
}

// Decode ASCII85 (PDF variant): whitespace ignored, 'z' = 4 zero bytes, ends with ~>
function decodeASCII85(buf) {
  const out = [];
  let tuple = 0, count = 0;
  for (let i = 0; i < buf.length; i++) {
    const ch = buf[i];
    if (ch === 0x7e) break;                                  // '~' terminator
    if (ch === 0x20 || ch === 0x0a || ch === 0x0d || ch === 0x09 || ch === 0x0c) continue;
    if (ch === 0x7a && count === 0) { out.push(0, 0, 0, 0); continue; } // 'z'
    if (ch < 0x21 || ch > 0x75) return null;
    tuple = tuple * 85 + (ch - 0x21);
    if (++count === 5) {
      out.push((tuple >>> 24) & 0xff, (tuple >>> 16) & 0xff, (tuple >>> 8) & 0xff, tuple & 0xff);
      tuple = 0; count = 0;
    }
  }
  if (count > 0) { // partial final group
    for (let i = count; i < 5; i++) tuple = tuple * 85 + 84;
    const bytes = [(tuple >>> 24) & 0xff, (tuple >>> 16) & 0xff, (tuple >>> 8) & 0xff, tuple & 0xff];
    out.push(...bytes.slice(0, count - 1));
  }
  return Buffer.from(out);
}

// Run a stream through its declared filter chain until fully decoded.
// Supports ASCII85Decode, ASCIIHexDecode, FlateDecode. Returns null if unsupported.
function decodeStream(rawData, filters) {
  let data = Buffer.from(rawData);
  for (const f of filters) {
    if (f === '/ASCII85Decode') {
      data = decodeASCII85(data);
      if (!data) return null;
    } else if (f === '/ASCIIHexDecode') {
      const hex = data.toString('latin1').replace(/[^0-9a-fA-F>]/g, '').replace(/>.*$/, '');
      data = Buffer.from(hex.length % 2 ? hex + '0' : hex, 'hex');
    } else if (f === '/FlateDecode') {
      try { data = zlib.inflateSync(data); } catch { return null; }
    } else {
      return null; // DCT, CCITT, LZW etc. — not handled here
    }
  }
  return data;
}

// One compression pass at a given knob value. Returns saved bytes (Uint8Array).
async function compressAt(inputBytes, t, { verbose = false } = {}) {
  const { scaleFlate, qFlate, grayFlate, scaleJpeg, qJpeg } = settingsFor(t);
  const pdfDoc = await PDFDocument.load(inputBytes, { updateMetadata: false });
  const context = pdfDoc.context;

  for (const [ref, obj] of context.enumerateIndirectObjects()) {
    if (!(obj instanceof PDFRawStream)) continue;
    const dict = obj.dict;
    if (dict.get(PDFName.of('Subtype'))?.toString() !== '/Image') continue;

    const width  = dict.get(PDFName.of('Width'))?.asNumber?.();
    const height = dict.get(PDFName.of('Height'))?.asNumber?.();
    const bpc    = dict.get(PDFName.of('BitsPerComponent'))?.asNumber?.();
    const cs     = dict.get(PDFName.of('ColorSpace'))?.toString?.();
    const filters = getFilterNames(dict);
    const rawData = obj.contents;

    // Never touch 1-bit / CCITT barcodes — must stay scannable
    if (filters.includes('/CCITTFaxDecode') || bpc === 1) continue;

    let newJpeg = null, isGray = false;

    const lastFilter = filters[filters.length - 1];

    // CASE 1: filter chain ending in FlateDecode over raw RGB raster
    // (covers plain /FlateDecode and chains like [/ASCII85Decode /FlateDecode])
    if (lastFilter === '/FlateDecode' && cs === '/DeviceRGB' && bpc === 8) {
      let pixels = decodeStream(rawData, filters);
      if (!pixels) continue;
      if (pixels.length === height * (width * 3 + 1)) {
        // Flate with PNG row predictors (one filter byte per row) — undo them
        pixels = unfilterPNG(pixels, width, height, 3);
        if (!pixels) continue;
      }
      if (pixels.length !== width * height * 3) continue;
      let s = sharp(pixels, { raw: { width, height, channels: 3 } });
      if (scaleFlate < 1) s = s.resize(Math.max(1, Math.round(width * scaleFlate)));
      if (grayFlate) { s = s.grayscale(); isGray = true; }
      newJpeg = await s.jpeg({ quality: qFlate, mozjpeg: true }).toBuffer();
    }
    // CASE 2: chain ending in DCTDecode (an embedded JPEG, possibly ASCII-wrapped)
    else if (lastFilter === '/DCTDecode') {
      const preFilters = filters.slice(0, -1);
      const jpegData = preFilters.length ? decodeStream(rawData, preFilters) : Buffer.from(rawData);
      if (!jpegData) continue;
      let s = sharp(jpegData);
      if (scaleJpeg < 1) s = s.resize(Math.max(1, Math.round(width * scaleJpeg)));
      const candidate = await s.jpeg({ quality: qJpeg, mozjpeg: true }).toBuffer();
      if (candidate.length < rawData.length) newJpeg = candidate;
    } else {
      continue; // unhandled encoding — keep as-is, never corrupt
    }

    if (newJpeg) {
      const meta = await sharp(newJpeg).metadata();
      dict.set(PDFName.of('Filter'), PDFName.of('DCTDecode'));
      dict.set(PDFName.of('ColorSpace'), PDFName.of(isGray ? 'DeviceGray' : 'DeviceRGB'));
      dict.set(PDFName.of('BitsPerComponent'), PDFNumber.of(8));
      dict.set(PDFName.of('Width'), PDFNumber.of(meta.width));
      dict.set(PDFName.of('Height'), PDFNumber.of(meta.height));
      dict.set(PDFName.of('Length'), PDFNumber.of(newJpeg.length));
      dict.delete(PDFName.of('DecodeParms'));
      context.assign(ref, PDFRawStream.of(dict, newJpeg));
      if (verbose) console.log(`  image ${ref}: ${rawData.length}B -> ${newJpeg.length}B`);
    }
  }

  return await pdfDoc.save({ useObjectStreams: true });
}

// Add an unused padding stream so the file reaches targetBytes (floor guarantee).
async function padTo(pdfBytes, targetBytes) {
  let padLen = targetBytes - pdfBytes.length;
  for (let i = 0; i < 6; i++) {                 // few iterations to converge
    if (padLen <= 0) return pdfBytes;
    const pdfDoc = await PDFDocument.load(pdfBytes, { updateMetadata: false });
    const ctx = pdfDoc.context;
    // incompressible random bytes in an unreferenced stream object
    const junk = require('crypto').randomBytes(padLen);
    const dict = ctx.obj({ Type: PDFName.of('Padding'), Length: junk.length });
    ctx.register(PDFRawStream.of(dict, junk));
    const out = await pdfDoc.save({ useObjectStreams: false });
    if (out.length >= targetBytes) return out;
    padLen += targetBytes - out.length;         // undershoot -> add the difference
    pdfBytes = out;
  }
  return pdfBytes;
}

/**
 * Compress PDF bytes in-memory to land inside [minKb, maxKb].
 * Always returns a valid PDF (Uint8Array) — never throws away the document.
 * @param {Buffer|Uint8Array} inputBytes
 * @param {{minKb?:number, maxKb?:number, verbose?:boolean}} [opts]
 * @returns {Promise<Uint8Array>}
 */
async function compressPdfBytes(inputBytes, opts = {}) {
  const MIN_BYTES = (opts.minKb ?? DEFAULT_MIN_KB) * 1024;
  const MAX_BYTES = (opts.maxKb ?? DEFAULT_MAX_KB) * 1024;
  const PAD_TARGET = Math.round((MIN_BYTES + MAX_BYTES) / 2);
  const verbose = !!opts.verbose;

  // 1) Try MAX quality first — if that's already <= max we may be done or need padding
  let best = null; // { t, bytes }
  const atMax = await compressAt(inputBytes, 1, { verbose });
  if (atMax.length <= MAX_BYTES) {
    best = { t: 1, bytes: atMax };
  } else {
    // 2) Check MIN quality — if even that is > max, accept the larger size.
    const atMin = await compressAt(inputBytes, 0, { verbose });
    if (atMin.length > MAX_BYTES) {
      return atMin; // couldn't fit window — return smallest achievable, never drop
    }
    // 3) Binary search the knob for a size inside the window (highest quality that fits)
    let lo = 0, hi = 1;
    best = { t: 0, bytes: atMin };
    for (let i = 0; i < 8; i++) {
      const mid = (lo + hi) / 2;
      const out = await compressAt(inputBytes, mid, { verbose });
      if (out.length <= MAX_BYTES) {
        best = { t: mid, bytes: out };   // fits — try higher quality
        lo = mid;
      } else {
        hi = mid;                        // too big — lower quality
      }
      if (best.bytes.length >= MIN_BYTES) break; // already inside window
    }
  }

  // 4) Floor guarantee: pad up if below min
  let outBytes = best.bytes;
  if (outBytes.length < MIN_BYTES) {
    outBytes = await padTo(outBytes, PAD_TARGET);
  }
  return outBytes;
}

/**
 * Compress a PDF on disk. Returns the output size in bytes.
 */
async function compressPdfFile(inputPath, outputPath, opts = {}) {
  const inputBytes = fs.readFileSync(inputPath);
  const outBytes = await compressPdfBytes(inputBytes, opts);
  fs.writeFileSync(outputPath, outBytes);
  return outBytes.length;
}

module.exports = { compressPdfBytes, compressPdfFile };

// ---------------- CLI: file or folder ----------------
async function main() {
  const [,, input, output] = process.argv;
  if (!input || !output) {
    console.error('Usage:');
    console.error('  node pdfCompressor.js <input.pdf>    <output.pdf>');
    console.error('  node pdfCompressor.js <input_folder> <output_folder>');
    process.exit(1);
  }

  const stat = fs.statSync(input);

  if (stat.isDirectory()) {
    fs.mkdirSync(output, { recursive: true });
    const pdfs = fs.readdirSync(input).filter(f => f.toLowerCase().endsWith('.pdf'));
    if (pdfs.length === 0) { console.error(`No PDF files found in ${input}`); process.exit(1); }
    console.log(`Found ${pdfs.length} PDF(s) in ${input}\n`);
    let ok = 0, failed = 0;
    for (const file of pdfs) {
      console.log(`=== ${file} ===`);
      try {
        const size = await compressPdfFile(path.join(input, file), path.join(output, file), { verbose: true });
        console.log(`Output: ${(size / 1024).toFixed(1)} KB`);
        ok++;
      } catch (err) {
        console.error(`  FAILED (${err.message}) — copying original instead`);
        fs.copyFileSync(path.join(input, file), path.join(output, file));
        failed++;
      }
      console.log('');
    }
    console.log(`Done. ${ok} compressed, ${failed} failed (copied as-is).`);
    return;
  }

  const inSize = fs.statSync(input).size;
  console.log(`Input : ${(inSize / 1024).toFixed(1)} KB`);
  const outSize = await compressPdfFile(input, output, { verbose: true });
  console.log(`Output: ${(outSize / 1024).toFixed(1)} KB`);
}

if (require.main === module) {
  main().catch(err => { console.error('Compression failed:', err); process.exit(1); });
}
