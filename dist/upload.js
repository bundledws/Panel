export async function parseMultipartBody(req, maxFileSize = 100 * 1024 * 1024) {
    const ct = req.headers["content-type"];
    if (!ct || !ct.startsWith("multipart/form-data"))
        throw new Error("Content-Type must be multipart/form-data");
    const boundary = ct.match(/boundary=(?:"([^"]+)"|([^;]+))/i)?.[1] ?? ct.match(/boundary=(?:"([^"]+)"|([^;]+))/i)?.[2];
    if (!boundary)
        throw new Error("Could not parse multipart boundary");
    const raw = await readBody(req);
    if (raw.length === 0)
        throw new Error("Empty request body");
    return parseBuffer(raw, boundary, maxFileSize);
}
async function readBody(req) {
    const chunks = [];
    for await (const c of req)
        chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    return Buffer.concat(chunks);
}
function parseBuffer(buffer, boundary, maxFileSize) {
    const delim = `--${boundary}`;
    const endDelim = `--${boundary}--`;
    const parts = [];
    let start = 0;
    while (start < buffer.length) {
        const di = buffer.indexOf(delim, start);
        if (di === -1)
            break;
        const ps = di + delim.length;
        if (buffer[ps] === 0x2d && buffer[ps + 1] === 0x2d)
            break;
        const cs = buffer[ps] === 0x0d && buffer[ps + 1] === 0x0a ? ps + 2 : buffer[ps] === 0x0a ? ps + 1 : ps;
        const nb = buffer.indexOf(`\r\n${delim}`, cs);
        if (nb === -1) {
            const ei = buffer.indexOf(endDelim, cs);
            parts.push(buffer.subarray(cs, ei !== -1 ? ei : undefined));
            break;
        }
        parts.push(buffer.subarray(cs, nb));
        start = nb + 2;
    }
    const result = { fields: {} };
    for (const part of parts) {
        const he = part.indexOf("\r\n\r\n");
        if (he === -1)
            continue;
        const hs = part.subarray(0, he).toString("utf8");
        const body = part.subarray(he + 4);
        const disp = hs.match(/content-disposition:\s*form-data;\s*name="([^"]*)"(?:;\s*filename="([^"]*)")?/i);
        if (!disp?.[1])
            continue;
        if (disp[2] !== undefined) {
            if (body.length > maxFileSize)
                throw new Error(`File exceeds maximum size of ${maxFileSize} bytes`);
            const ctMatch = hs.match(/content-type:\s*([^\r\n]+)/i);
            result.file = { filename: disp[2], data: body, contentType: ctMatch?.[1]?.trim() ?? "application/octet-stream" };
        }
        else {
            result.fields[disp[1]] = body.toString("utf8").replace(/\r?\n$/, "");
        }
    }
    return result;
}
//# sourceMappingURL=upload.js.map