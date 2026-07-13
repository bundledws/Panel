import fs from "node:fs";
// ZIP constants
const EOCD_SIG = 0x06054b50;
const CENTRAL_DIR_ENTRY_SIG = 0x02014b50;
const MAX_UNCOMPRESSED_TOTAL = 1_000_000_000; // 1GB
const MAX_SINGLE_ENTRY = 200_000_000; // 200MB
const MAX_COMPRESSION_RATIO = 100;
const MAX_ENTRY_COUNT = 10_000;
function readU32(buf, off) {
    return buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24);
}
function readU16(buf, off) {
    return buf[off] | (buf[off + 1] << 8);
}
/** Read the ZIP central directory from the end of the file and return all entries. */
function readCentralEntries(fd, size) {
    // Find EOCD: search backwards from end of file up to 64KB (max EOCD comment length)
    const maxSearch = Math.min(size, 65557);
    const buf = Buffer.alloc(maxSearch);
    fs.readSync(fd, buf, 0, maxSearch, size - maxSearch);
    let eocdOffset = -1;
    for (let i = maxSearch - 22; i >= 0; i--) {
        if (readU32(buf, i) === EOCD_SIG) {
            eocdOffset = size - maxSearch + i;
            break;
        }
    }
    if (eocdOffset === -1)
        throw new Error("Invalid ZIP: EOCD not found");
    const centralOffset = readU32(buf, eocdOffset - (size - maxSearch) + 16);
    const numEntries = readU16(buf, eocdOffset - (size - maxSearch) + 10);
    if (numEntries > MAX_ENTRY_COUNT)
        throw new Error(`Zip bomb detected: ${numEntries} entries (max ${MAX_ENTRY_COUNT})`);
    // Read central directory
    const cdSize = readU32(buf, eocdOffset - (size - maxSearch) + 12);
    const cdBuf = Buffer.alloc(cdSize);
    fs.readSync(fd, cdBuf, 0, cdSize, centralOffset);
    const entries = [];
    let off = 0;
    for (let i = 0; i < numEntries; i++) {
        if (readU32(cdBuf, off) !== CENTRAL_DIR_ENTRY_SIG)
            throw new Error(`Invalid ZIP: bad central directory entry at index ${i}`);
        const nameLen = readU16(cdBuf, off + 28);
        const extraLen = readU16(cdBuf, off + 30);
        const commentLen = readU16(cdBuf, off + 32);
        const compressedSize = readU32(cdBuf, off + 20);
        const uncompressedSize = readU32(cdBuf, off + 24);
        const fileName = cdBuf.toString("utf8", off + 46, off + 46 + nameLen);
        entries.push({ fileName, compressedSize, uncompressedSize });
        off += 46 + nameLen + extraLen + commentLen;
    }
    return entries;
}
export async function inspectZip(zipPath) {
    if (!fs.existsSync(zipPath))
        throw new Error("ZIP file not found");
    const stat = fs.statSync(zipPath);
    if (stat.size === 0)
        throw new Error("ZIP file is empty");
    const fd = fs.openSync(zipPath, "r");
    try {
        const entries = readCentralEntries(fd, stat.size);
        if (entries.length === 0)
            throw new Error("ZIP file contains no entries");
        if (entries.length > MAX_ENTRY_COUNT)
            throw new Error(`Zip bomb detected: ${entries.length} entries (max ${MAX_ENTRY_COUNT})`);
        let totalCompressed = 0;
        let totalUncompressed = 0;
        let maxRatio = 0;
        let suspicious = "";
        for (const entry of entries) {
            totalCompressed += entry.compressedSize;
            totalUncompressed += entry.uncompressedSize;
            if (entry.uncompressedSize > MAX_SINGLE_ENTRY) {
                throw new Error(`Zip bomb detected: entry "${entry.fileName}" is ${entry.uncompressedSize} bytes uncompressed (max ${MAX_SINGLE_ENTRY})`);
            }
            if (entry.compressedSize > 0 && entry.uncompressedSize > entry.compressedSize) {
                const ratio = entry.uncompressedSize / entry.compressedSize;
                if (ratio > maxRatio)
                    maxRatio = ratio;
                if (ratio > MAX_COMPRESSION_RATIO) {
                    throw new Error(`Zip bomb detected: entry "${entry.fileName}" has compression ratio of ${ratio.toFixed(0)}:1 (max ${MAX_COMPRESSION_RATIO}:1)`);
                }
            }
            const lower = entry.fileName.toLowerCase();
            if (lower.endsWith(".zip") || lower.endsWith(".7z") || lower.endsWith(".tar.gz") || lower.endsWith(".rar")) {
                suspicious = `Archive contains nested archive: "${entry.fileName}"`;
            }
        }
        if (totalUncompressed > MAX_UNCOMPRESSED_TOTAL) {
            throw new Error(`Zip bomb detected: total uncompressed size is ${totalUncompressed} bytes (max ${MAX_UNCOMPRESSED_TOTAL})`);
        }
        if (suspicious)
            throw new Error(suspicious);
        return { safe: true, entryCount: entries.length, totalUncompressed, totalCompressed };
    }
    finally {
        fs.closeSync(fd);
    }
}
//# sourceMappingURL=zip-inspect.js.map