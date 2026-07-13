import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import zlib from "node:zlib";

// ============================================================
// CRC-32 Lookup Table (pure JS, no dependencies)
// ============================================================
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC32_TABLE[i] = c;
}

function crc32(buf: Buffer): number {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// ============================================================
// ZIP Constants
// ============================================================
const LOCAL_FILE_HEADER_SIG = 0x04034b50;
const CENTRAL_DIR_ENTRY_SIG = 0x02014b50;
const EOCD_SIG = 0x06054b50;
const COMPRESSION_DEFLATE = 8;

// ============================================================
// Write helpers (little-endian)
// ============================================================
function writeU32(buf: Buffer, off: number, val: number): void {
  buf[off] = val & 0xFF;
  buf[off + 1] = (val >>> 8) & 0xFF;
  buf[off + 2] = (val >>> 16) & 0xFF;
  buf[off + 3] = (val >>> 24) & 0xFF;
}
function writeU16(buf: Buffer, off: number, val: number): void {
  buf[off] = val & 0xFF;
  buf[off + 1] = (val >>> 8) & 0xFF;
}

// ============================================================
// Check if a relative path should be excluded
// ============================================================
function isExcluded(relPath: string, excludes: string[]): boolean {
  const normalized = relPath.replace(/\\/g, "/");
  for (const ex of excludes) {
    if (normalized === ex) return true;
    if (normalized.startsWith(ex + "/")) return true;
    if (normalized === ex + "/" || normalized === ex) return true;
  }
  return false;
}

// ============================================================
// Main exported function — streams ZIP directly to disk
// ============================================================
export async function createBackupZip(
  srcDir: string,
  destPath: string,
  excludes: string[]
): Promise<string> {
  // Strategy 1: Try system `zip` binary (efficient, streams to disk)
  try {
    await new Promise<void>((resolve, reject) => {
      const args = ["-r", "-q", destPath, ".", "-x"];
      for (const ex of excludes) {
        args.push(ex + "/*");
      }
      const child = spawn("zip", args, { cwd: srcDir, timeout: 60000 });
      let stderr = "";
      child.stderr.on("data", (c: Buffer) => { stderr += c.toString(); });
      child.on("close", (code) => {
        if (code !== 0) reject(new Error(stderr || `zip exited with code ${code}`));
        else resolve();
      });
      child.on("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "ENOENT") reject(err);
        else reject(err);
      });
    });
    return destPath;
  } catch (err: any) {
    if (err.code !== "ENOENT" && !err.message?.includes("spawn zip ENOENT")) {
      throw err;
    }
  }

  // Strategy 2: Pure Node.js streaming ZIP writer
  // Writes each file immediately to disk, no in-memory accumulation
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  const writeStream = fs.createWriteStream(destPath);
  const centralEntries: Buffer[] = [];
  let localOffset = 0;

  type WalkItem = { dir: string; names: string[]; index: number };
  const stack: WalkItem[] = [];

  // Bootstrap directory walk
  try {
    const names = fs.readdirSync(srcDir);
    stack.push({ dir: srcDir, names, index: 0 });
  } catch {
    writeStream.destroy();
    throw new Error("Cannot read source directory");
  }

  try {
    while (stack.length > 0) {
      const item = stack[stack.length - 1];

      if (item.index >= item.names.length) {
        stack.pop();
        continue;
      }

      const name = item.names[item.index++];
      const fullPath = path.join(item.dir, name);
      const relPath = path.relative(srcDir, fullPath).replace(/\\/g, "/");

      if (isExcluded(relPath, excludes)) continue;

      let stat: fs.Stats;
      try { stat = fs.statSync(fullPath); } catch { continue; }

      if (stat.isDirectory()) {
        try {
          const subNames = fs.readdirSync(fullPath);
          stack.push({ dir: fullPath, names: subNames, index: 0 });
        } catch { /* skip unreadable dirs */ }
      } else if (stat.isFile()) {
        // Read file data, compress, write immediately
        let fileData: Buffer;
        try { fileData = fs.readFileSync(fullPath); } catch { continue; }

        const fileNameBuf = Buffer.from(relPath, "utf8");
        const compressed = zlib.deflateRawSync(fileData, { level: 6 });
        const checksum = crc32(fileData);
        const compSize = compressed.length;
        const uncompSize = fileData.length;

        // Local File Header (30 bytes + filename)
        const localHeader = Buffer.alloc(30 + fileNameBuf.length);
        writeU32(localHeader, 0, LOCAL_FILE_HEADER_SIG);
        writeU16(localHeader, 4, 20);
        writeU16(localHeader, 6, 0);
        writeU16(localHeader, 8, COMPRESSION_DEFLATE);
        writeU16(localHeader, 10, 0);
        writeU16(localHeader, 12, 0);
        writeU32(localHeader, 14, checksum);
        writeU32(localHeader, 18, compSize);
        writeU32(localHeader, 22, uncompSize);
        writeU16(localHeader, 26, fileNameBuf.length);
        writeU16(localHeader, 28, 0);
        fileNameBuf.copy(localHeader, 30);

        // Write local header + compressed data to stream immediately
        writeStream.write(localHeader);
        writeStream.write(compressed);

        // Central Directory Entry (46 bytes + filename)
        const centralEntry = Buffer.alloc(46 + fileNameBuf.length);
        writeU32(centralEntry, 0, CENTRAL_DIR_ENTRY_SIG);
        writeU16(centralEntry, 4, 20);
        writeU16(centralEntry, 6, 20);
        writeU16(centralEntry, 8, 0);
        writeU16(centralEntry, 10, COMPRESSION_DEFLATE);
        writeU16(centralEntry, 12, 0);
        writeU16(centralEntry, 14, 0);
        writeU32(centralEntry, 16, checksum);
        writeU32(centralEntry, 20, compSize);
        writeU32(centralEntry, 24, uncompSize);
        writeU16(centralEntry, 28, fileNameBuf.length);
        writeU16(centralEntry, 30, 0);
        writeU16(centralEntry, 32, 0);
        writeU16(centralEntry, 34, 0);
        writeU16(centralEntry, 36, 0);
        writeU32(centralEntry, 38, 0);
        writeU32(centralEntry, 42, localOffset);
        fileNameBuf.copy(centralEntry, 46);

        centralEntries.push(centralEntry);
        localOffset += 30 + fileNameBuf.length + compSize;
      }
    }

    // Write Central Directory
    const centralDir = Buffer.concat(centralEntries);
    const centralDirSize = centralDir.length;
    writeStream.write(centralDir);

    // Write End of Central Directory (22 bytes)
    const eocd = Buffer.alloc(22);
    writeU32(eocd, 0, EOCD_SIG);
    writeU16(eocd, 4, 0);
    writeU16(eocd, 6, 0);
    writeU16(eocd, 8, centralEntries.length);
    writeU16(eocd, 10, centralEntries.length);
    writeU32(eocd, 12, centralDirSize);
    writeU32(eocd, 16, localOffset);
    writeU16(eocd, 20, 0);
    writeStream.write(eocd);

    writeStream.end();
    await new Promise<void>((resolve, reject) => {
      writeStream.on("finish", resolve);
      writeStream.on("error", reject);
    });
    return destPath;
  } catch (err: any) {
    writeStream.destroy();
    throw new Error(`Backup failed: ${err.message}`);
  }
}
