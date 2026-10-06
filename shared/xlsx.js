// 0.9.2 账号导入导出：零第三方依赖的最小 XLSX 读写 + 分隔文本（CSV/TSV）解析。
// XLSX 写入：STORE（不压缩）ZIP + CRC32 + 最小 SpreadsheetML（inlineStr，无需 sharedStrings/styles）。
// XLSX 读取：复用 shared/zip.js parseZip，兼容 inlineStr / sharedStrings / 数字单元格。
import { parseZip } from "./zip.js";

// ---------- CRC32 ----------
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (let i = 0; i < buffer.length; i += 1) {
    crc = CRC_TABLE[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// ---------- 最小 ZIP 写入（STORE）----------
/**
 * 打包文件为 ZIP Buffer（仅 STORE，不压缩）。
 * @param {Array<{path: string, data: Buffer}>} entries
 * @returns {Buffer}
 */
export function buildZip(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.path, "utf8");
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(String(entry.data), "utf8");
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // 解压所需版本 2.0
    local.writeUInt16LE(0x0800, 6); // flags：UTF-8 文件名
    local.writeUInt16LE(0, 8); // method: STORE
    local.writeUInt16LE(0, 10); // mod time
    local.writeUInt16LE(0, 12); // mod date（1980-01-01 基准，固定为 0 可被 Excel 接受）
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed size
    local.writeUInt32LE(data.length, 22); // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra len
    localParts.push(local, nameBuf, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // 制作版本
    central.writeUInt16LE(20, 6); // 所需版本
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk
    central.writeUInt16LE(0, 36); // internal attrs
    central.writeUInt32LE(0, 38); // external attrs
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, nameBuf);

    offset += local.length + nameBuf.length + data.length;
  }

  const centralBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralBuf, eocd]);
}

// ---------- XML 工具 ----------
function xmlEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function xmlUnescape(value) {
  return String(value)
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number.parseInt(dec, 10)))
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&amp;", "&");
}

function colToIndex(ref) {
  const letters = /^([A-Z]+)/.exec(ref || "");
  if (!letters) return 0;
  let index = 0;
  for (const ch of letters[1]) {
    index = index * 26 + (ch.charCodeAt(0) - 64);
  }
  return index - 1;
}

// ---------- XLSX 写入 ----------
const CONTENT_TYPES_XML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`;

const ROOT_RELS_XML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`;

function workbookXml(sheetName) {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="${xmlEscape(sheetName)}" sheetId="1" r:id="rId1"/></sheets>
</workbook>`;
}

const WORKBOOK_RELS_XML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`;

const COL_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

function colLetter(index) {
  let n = index + 1;
  let out = "";
  while (n > 0) {
    const rem = (n - 1) % 26;
    out = COL_LETTERS[rem] + out;
    n = Math.floor((n - 1) / 26);
  }
  return out;
}

function sheetXml(rows) {
  const rowXml = rows
    .map((row, rowIndex) => {
      const cells = row
        .map((cell, colIndex) => {
          const ref = `${colLetter(colIndex)}${rowIndex + 1}`;
          return `<c r="${ref}" t="inlineStr"><is><t xml:space="preserve">${xmlEscape(cell)}</t></is></c>`;
        })
        .join("");
      return `<row r="${rowIndex + 1}">${cells}</row>`;
    })
    .join("");
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>${rowXml}</sheetData>
</worksheet>`;
}

/**
 * 构造最小 XLSX Buffer。所有单元格按 inlineStr 文本写入（数字文本在 Excel 中可正常参与运算识别）。
 * @param {string[][]} rows 行数组（首行建议为表头）
 * @param {{ sheetName?: string }} [options]
 * @returns {Buffer}
 */
export function buildXlsx(rows, { sheetName = "Sheet1" } = {}) {
  const entries = [
    { path: "[Content_Types].xml", data: Buffer.from(CONTENT_TYPES_XML, "utf8") },
    { path: "_rels/.rels", data: Buffer.from(ROOT_RELS_XML, "utf8") },
    { path: "xl/workbook.xml", data: Buffer.from(workbookXml(sheetName), "utf8") },
    { path: "xl/_rels/workbook.xml.rels", data: Buffer.from(WORKBOOK_RELS_XML, "utf8") },
    { path: "xl/worksheets/sheet1.xml", data: Buffer.from(sheetXml(rows), "utf8") },
  ];
  return buildZip(entries);
}

// ---------- XLSX 读取 ----------
function extractTagAll(xml, tag) {
  const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, "g");
  const out = [];
  let match;
  while ((match = re.exec(xml)) !== null) out.push(match[1]);
  return out;
}

function extractText(xml) {
  // <t> 可能带属性（xml:space），也可能出现多段。
  const parts = [];
  const re = /<t\b[^>]*>([\s\S]*?)<\/t>/g;
  let match;
  while ((match = re.exec(xml)) !== null) parts.push(xmlUnescape(match[1]));
  return parts.join("");
}

/**
 * 解析 XLSX Buffer 为行数组（仅取第一个工作表）。
 * 兼容 inlineStr、sharedStrings（t="s"）与数字单元格；按 r= 引用定位列，空单元格补位。
 * @param {Buffer} buffer
 * @returns {string[][]}
 */
export function parseXlsx(buffer) {
  const files = parseZip(buffer);
  const byPath = new Map(files.map((file) => [file.path.replace(/^\/+/, ""), file.data]));
  const sheetData =
    byPath.get("xl/worksheets/sheet1.xml") ||
    files.find((file) => /^xl\/worksheets\/sheet\d+\.xml$/.test(file.path))?.data;
  if (!sheetData) throw new Error("XLSX 缺少工作表数据");
  const sheetXmlText = sheetData.toString("utf8");

  // 共享字符串（我们自己的导出不产生，但需兼容 Excel/WPS 另存的文件）。
  let shared = [];
  const sharedData = byPath.get("xl/sharedStrings.xml");
  if (sharedData) {
    shared = extractTagAll(sharedData.toString("utf8"), "si").map((si) => extractText(si));
  }

  const rows = [];
  const rowBlocks = extractTagAll(sheetXmlText, "row");
  for (const rowBlock of rowBlocks) {
    const cells = [];
    const cellRe = /<c\b([^>]*)>([\s\S]*?)<\/c>|<c\b([^>]*)\/>/g;
    let cellMatch;
    while ((cellMatch = cellRe.exec(rowBlock)) !== null) {
      const attrs = cellMatch[1] ?? cellMatch[3] ?? "";
      const inner = cellMatch[2] ?? "";
      const refMatch = /r="([A-Z]+\d+)"/.exec(attrs);
      const colIndex = refMatch ? colToIndex(refMatch[1]) : cells.length;
      const typeMatch = /t="([^"]+)"/.exec(attrs);
      const type = typeMatch ? typeMatch[1] : "n";
      let value = "";
      if (type === "inlineStr") {
        value = extractText(inner);
      } else if (type === "s") {
        const vMatch = /<v>([\s\S]*?)<\/v>/.exec(inner);
        value = vMatch ? shared[Number(vMatch[1])] ?? "" : "";
      } else if (type === "str") {
        const vMatch = /<v>([\s\S]*?)<\/v>/.exec(inner);
        value = vMatch ? xmlUnescape(vMatch[1]) : "";
      } else {
        const vMatch = /<v>([\s\S]*?)<\/v>/.exec(inner);
        if (vMatch) value = xmlUnescape(vMatch[1]);
      }
      while (cells.length < colIndex) cells.push("");
      cells[colIndex] = value;
    }
    rows.push(cells);
  }
  return rows;
}

/** 嗅探是否为 XLSX（ZIP 魔数 PK\x03\x04）。 */
export function looksLikeXlsx(buffer) {
  return Buffer.isBuffer(buffer) && buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04;
}

// ---------- 分隔文本（CSV / TSV / 分号）----------
/**
 * 解析分隔文本：按首行自动检测制表符/分号/逗号；支持双引号包裹与 "" 转义；跳过纯空行。
 * @param {string} text
 * @returns {string[][]}
 */
export function parseDelimited(text) {
  const normalized = String(text).replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n");
  const firstLine = normalized.split("\n", 1)[0] || "";
  let delimiter = ",";
  if (firstLine.includes("\t")) delimiter = "\t";
  else if ((firstLine.match(/;/g) || []).length > (firstLine.match(/,/g) || []).length) delimiter = ";";

  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < normalized.length; i += 1) {
    const ch = normalized[i];
    if (inQuotes) {
      if (ch === '"') {
        if (normalized[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === delimiter) {
      row.push(field);
      field = "";
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += ch;
    }
  }
  row.push(field);
  rows.push(row);

  return rows
    .map((cells) => cells.map((cell) => cell.trim()))
    .filter((cells) => cells.some((cell) => cell !== ""));
}

/** 序列化为分隔文本（默认逗号 CSV；含分隔符/引号/换行的字段自动双引号包裹）。 */
export function toDelimited(rows, delimiter = ",") {
  return rows
    .map((row) =>
      row
        .map((cell) => {
          const value = String(cell ?? "");
          return /[",\n\r\t;]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
        })
        .join(delimiter),
    )
    .join("\r\n");
}
