import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const baseDir = "/Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee";
const inventoryDir = path.join(baseDir, "full-inventory");
const outputDir = "/Users/itsmac/Desktop/auto-scan-vuln-lic/outputs/coroot-ee-binary-analysis";
const outputPath = path.join(outputDir, "coroot-ee-binary-analysis.xlsx");

const MAX_CELL = 32000;
const CHUNK_ROWS = 5000;

const files = {
  report: path.join(baseDir, "full-inventory-report.md"),
  summary: path.join(inventoryDir, "inventory-summary.json"),
  apiRoutes: path.join(inventoryDir, "api-routes-final.tsv"),
  urls: path.join(inventoryDir, "urls-all.tsv"),
  paths: path.join(inventoryDir, "paths-all-candidates.tsv"),
  sourcePaths: path.join(inventoryDir, "source-file-paths-all.txt"),
  secrets: path.join(inventoryDir, "secret-scan.tsv"),
  secretNames: path.join(inventoryDir, "secret-key-names-config-candidates.tsv"),
  malware: path.join(inventoryDir, "malware-indicators.tsv"),
  dynamicLibraries: path.join(inventoryDir, "dynamic-libraries.txt"),
  enterpriseSymbols: path.join(inventoryDir, "enterprise-handlers-and-license-symbols.txt"),
  highValueSymbols: path.join(inventoryDir, "high-value-go-symbols.txt"),
  readelfHeader: path.join(inventoryDir, "readelf-header.txt"),
  readelfProgramHeaders: path.join(inventoryDir, "readelf-program-headers.txt"),
  readelfSections: path.join(inventoryDir, "readelf-sections.txt"),
  readelfDynamic: path.join(inventoryDir, "readelf-dynamic.txt"),
  readelfDynsyms: path.join(inventoryDir, "readelf-dynsyms.txt"),
  readelfSymbols: path.join(inventoryDir, "readelf-symbols.txt"),
  rzImports: path.join(inventoryDir, "rz-bin-imports.txt"),
  rzInfo: path.join(inventoryDir, "rz-bin-info.txt"),
  redressInfo: path.join(inventoryDir, "redress-info.txt"),
  redressGoMod: path.join(inventoryDir, "redress-gomod.txt"),
  grypeJson: path.join(inventoryDir, "grype.json"),
  syftJson: path.join(inventoryDir, "syft-sbom.json"),
  govulnText: path.join(inventoryDir, "govulncheck-binary.txt"),
  govulnJson: path.join(inventoryDir, "govulncheck-binary.json"),
  rawStrings: path.join(inventoryDir, "strings-offsets-n6.txt"),
};

function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function cleanCell(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "number" || typeof value === "boolean" || value instanceof Date) return value;
  const s = String(value).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, " ");
  return s.length > MAX_CELL ? s.slice(0, MAX_CELL) : s;
}

function truncationInfo(value) {
  const s = value === null || value === undefined ? "" : String(value).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, " ");
  return {
    preview: s.length > MAX_CELL ? s.slice(0, MAX_CELL) : s,
    originalLength: s.length,
    sha256: sha256(s),
    truncated: s.length > MAX_CELL,
  };
}

async function readText(file) {
  return fs.readFile(file, "utf8");
}

async function readLines(file) {
  const text = await readText(file);
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").filter((line) => line.length > 0);
}

async function readTsv(file) {
  const lines = await readLines(file);
  if (lines.length === 0) return { headers: [], rows: [] };
  const headers = lines[0].split("\t");
  const rows = lines.slice(1).map((line) => {
    const parts = line.split("\t");
    while (parts.length < headers.length) parts.push("");
    return parts.slice(0, headers.length);
  });
  return { headers, rows };
}

function readJsonStream(text) {
  const objects = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === "\"") {
        inString = false;
      }
      continue;
    }
    if (ch === "\"") {
      inString = true;
      continue;
    }
    if (ch === "{") {
      if (depth === 0) start = i;
      depth++;
      continue;
    }
    if (ch === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        objects.push(JSON.parse(text.slice(start, i + 1)));
        start = -1;
      }
    }
  }

  return objects;
}

function matrixWidth(matrix) {
  let width = 1;
  for (const row of matrix) {
    if (row.length > width) width = row.length;
  }
  return width;
}

function normalizeMatrix(matrix) {
  const width = matrixWidth(matrix);
  return matrix.map((row) => {
    const out = row.map(cleanCell);
    while (out.length < width) out.push("");
    return out;
  });
}

async function writeMatrix(sheet, matrix, startRow = 0, startCol = 0) {
  const normalized = normalizeMatrix(matrix);
  if (!normalized.length) return;
  const width = matrixWidth(normalized);
  for (let i = 0; i < normalized.length; i += CHUNK_ROWS) {
    const chunk = normalized.slice(i, i + CHUNK_ROWS);
    sheet.getRangeByIndexes(startRow + i, startCol, chunk.length, width).values = chunk;
  }
}

function styleSheet(sheet, rows, cols, widths = []) {
  sheet.showGridLines = false;
  if (rows > 1) sheet.freezePanes.freezeRows(1);
  const header = sheet.getRangeByIndexes(0, 0, 1, Math.max(1, cols));
  header.format.fill.color = "#17365D";
  header.format.font.color = "#FFFFFF";
  header.format.font.bold = true;
  header.format.wrapText = true;
  for (let c = 0; c < Math.max(1, cols); c++) {
    const width = widths[c] ?? (c === 0 ? 180 : 220);
    sheet.getRangeByIndexes(0, c, Math.max(1, rows), 1).format.columnWidthPx = width;
  }
}

async function addDataSheet(workbook, name, headers, rows, widths = []) {
  const sheet = workbook.worksheets.add(name);
  const matrix = [headers, ...rows];
  await writeMatrix(sheet, matrix);
  styleSheet(sheet, matrix.length, matrixWidth(matrix), widths);
  return sheet;
}

async function addTsvSheet(workbook, name, file, widths = []) {
  const { headers, rows } = await readTsv(file);
  return addDataSheet(workbook, name, headers, rows, widths);
}

async function addLineSheet(workbook, name, file, headers, mapper, widths = []) {
  const lines = await readLines(file);
  const rows = lines.map(mapper);
  return addDataSheet(workbook, name, headers, rows, widths);
}

function parseStringsLine(line) {
  const match = line.match(/^\s*([0-9a-fA-F]+)\s+(.*)$/);
  const offset = match ? `0x${match[1]}` : "";
  const value = match ? match[2] : line;
  const info = truncationInfo(value);
  return [offset, info.preview, info.originalLength, info.sha256, info.truncated ? "yes" : "no"];
}

function parseSymbolLine(line) {
  const match = line.match(/^\s*([0-9a-fA-F]+)?\s*([A-Za-z?])?\s*(.*)$/);
  if (!match) return ["", "", line];
  return [match[1] ? `0x${match[1]}` : "", match[2] ?? "", match[3] ?? ""];
}

function parseReadelfLine(line, index) {
  return [index + 1, line];
}

async function buildSummaryRows() {
  const summary = JSON.parse(await readText(files.summary));
  return [
    ["Target", "/Users/itsmac/Documents/Binary/coroot-ee"],
    ["Analysis time", "2026-06-13 Asia/Ho_Chi_Minh"],
    ["Binary SHA256", "8897486973706d2850f9ec8fbc8767d0dadce96983502ce7c047ebd35487813d"],
    ["Format", "ELF64 Linux ARM64 Go executable"],
    ["Go version", "go1.25.11"],
    ["Main module", "github.com/coroot/enterprise"],
    ["Version ldflag", "main.version=1.22.0"],
    ["Strings extracted", summary.strings_count],
    ["Unique URLs", summary.unique_urls],
    ["Path candidates", summary.unique_path_candidates],
    ["Source paths", summary.source_paths],
    ["High-confidence API routes", summary.api_routes_final_high_confidence],
    ["Secret findings", summary.secret_findings_total],
    ["Dynamic libraries", summary.dynamic_libraries.join(", ")],
    ["Malware direct native exec imports", summary.malware_indicator_counts_clean.direct_native_exec_import],
    ["Malware Go process exec symbols", summary.malware_indicator_counts_clean.go_process_exec_symbols],
    ["Malware miner/C2 keywords", summary.malware_indicator_counts_clean.miner_c2_keywords],
    ["Notes", "Static analysis only; Linux ARM64 binary was not executed."],
  ];
}

async function buildBinaryStructureRows() {
  const chunks = [
    ["readelf-header", await readText(files.readelfHeader)],
    ["rz-bin-info", await readText(files.rzInfo)],
    ["redress-info", await readText(files.redressInfo)],
  ];
  const rows = [
    ["File", "/Users/itsmac/Documents/Binary/coroot-ee"],
    ["Size bytes", "75105928"],
    ["SHA256", "8897486973706d2850f9ec8fbc8767d0dadce96983502ce7c047ebd35487813d"],
    ["Architecture", "ARM AArch64"],
    ["OS", "Linux"],
    ["Interpreter", "/lib/ld-linux-aarch64.so.1"],
    ["Entry point", "0x402c00"],
    ["Dynamically linked", "yes"],
    ["Stripped", "false"],
    ["Debug info", "present"],
    ["NX", "true"],
    ["PIE", "false"],
    ["RELRO", "partial"],
  ];
  for (const [label, text] of chunks) {
    rows.push([""]);
    rows.push([label, ""]);
    for (const line of text.split(/\r?\n/).filter(Boolean)) rows.push(["", line]);
  }
  return rows;
}

function govulnRowsFromText(text) {
  const blocks = text.split(/\n(?=Vulnerability #)/g).filter((b) => b.includes("Vulnerability #"));
  return blocks.map((block) => {
    const id = block.match(/Vulnerability #\d+:\s*(GO-\d+-\d+)/)?.[1] ?? "";
    const summary = block.match(/\n\s+([^\n]+(?:\n\s{4}[^\n]+)*)\n\s+More info:/)?.[1]?.replace(/\s+/g, " ").trim() ?? "";
    const moreInfo = block.match(/More info:\s*(\S+)/)?.[1] ?? "";
    const module = block.match(/Module:\s*([^\n]+)/)?.[1]?.trim() ?? "";
    const found = block.match(/Found in:\s*([^\n]+)/)?.[1]?.trim() ?? "";
    const fixed = block.match(/Fixed in:\s*([^\n]+)/)?.[1]?.trim() ?? "";
    const symbols = [...block.matchAll(/#\d+:\s*([^\n]+)/g)].map((m) => m[1].trim()).join("; ");
    return [id, module, found, fixed, summary, moreInfo, symbols];
  });
}

async function buildGovulnFindingRows() {
  const textRows = govulnRowsFromText(await readText(files.govulnText));
  const events = readJsonStream(await readText(files.govulnJson));
  const findingEvents = events.filter((e) => e.finding).map((e) => e.finding);
  const byId = new Map();
  for (const f of findingEvents) {
    const id = f.osv ?? f.osvId ?? f.id ?? "";
    if (!id || byId.has(id)) continue;
    byId.set(id, f);
  }
  return textRows.map((row) => {
    const id = row[0];
    const f = byId.get(id);
    const traceCount = f?.trace ? f.trace.length : "";
    return [...row, traceCount];
  });
}

async function buildGrypeRows() {
  const data = JSON.parse(await readText(files.grypeJson));
  return data.matches.map((m) => {
    const v = m.vulnerability ?? {};
    const a = m.artifact ?? {};
    const fixVersions = v.fix?.versions?.join(", ") ?? "";
    const related = (m.relatedVulnerabilities ?? []).map((rv) => rv.id).join(", ");
    const epss = v.epss?.[0]?.epss ?? "";
    const risk = v.risk ?? "";
    const urls = (v.urls ?? []).slice(0, 5).join("\n");
    return [
      a.name ?? "",
      a.version ?? "",
      a.type ?? "",
      v.id ?? "",
      related,
      v.severity ?? "",
      fixVersions,
      epss,
      risk,
      v.description ?? "",
      urls,
    ];
  });
}

async function buildSbomRows() {
  const data = JSON.parse(await readText(files.syftJson));
  return data.artifacts.map((a) => {
    const locations = (a.locations ?? []).map((l) => l.path ?? l.accessPath ?? "").join("\n");
    const licenses = (a.licenses ?? []).map((l) => typeof l === "string" ? l : l.value ?? l.spdxExpression ?? "").join(", ");
    return [
      a.name ?? "",
      a.version ?? "",
      a.type ?? "",
      a.language ?? "",
      a.metadataType ?? "",
      licenses,
      a.purl ?? "",
      locations,
    ];
  });
}

async function buildArtifactIndexRows() {
  const entries = [
    ["Report markdown", files.report],
    ["Inventory summary JSON", files.summary],
    ["API routes", files.apiRoutes],
    ["URLs", files.urls],
    ["Path candidates", files.paths],
    ["Source paths", files.sourcePaths],
    ["Secret scan", files.secrets],
    ["Secret/config names", files.secretNames],
    ["Malware indicators", files.malware],
    ["Dynamic libraries", files.dynamicLibraries],
    ["Enterprise symbols", files.enterpriseSymbols],
    ["High-value symbols", files.highValueSymbols],
    ["readelf header", files.readelfHeader],
    ["readelf program headers", files.readelfProgramHeaders],
    ["readelf sections", files.readelfSections],
    ["readelf dynamic", files.readelfDynamic],
    ["readelf dynsyms", files.readelfDynsyms],
    ["readelf symbols", files.readelfSymbols],
    ["rizin imports", files.rzImports],
    ["Syft SBOM JSON", files.syftJson],
    ["Grype JSON", files.grypeJson],
    ["govulncheck binary text", files.govulnText],
    ["Raw strings with offsets", files.rawStrings],
  ];
  const rows = [];
  for (const [name, file] of entries) {
    const stat = await fs.stat(file);
    rows.push([name, file, stat.size]);
  }
  return rows;
}

async function main() {
  const workbook = Workbook.create();

  await addDataSheet(workbook, "Summary", ["Metric", "Value"], await buildSummaryRows(), [240, 760]);
  await addDataSheet(workbook, "Binary Structure", ["Field", "Value"], await buildBinaryStructureRows(), [240, 900]);
  await addTsvSheet(workbook, "API Routes", files.apiRoutes, [260, 110, 170, 170, 420, 560]);
  await addTsvSheet(workbook, "URLs", files.urls, [120, 760]);
  await addTsvSheet(workbook, "Path Candidates", files.paths, [120, 900]);
  await addLineSheet(workbook, "Source Paths", files.sourcePaths, ["source_path"], (line) => [line], [900]);
  await addTsvSheet(workbook, "Secrets", files.secrets, [190, 120, 260, 330, 460]);
  await addTsvSheet(workbook, "Secret Config Names", files.secretNames, [180, 180, 220, 760]);
  await addDataSheet(
    workbook,
    "Govulncheck Direct",
    ["id", "module", "found_in", "fixed_in", "summary", "more_info", "sample_symbols", "trace_count"],
    await buildGovulnFindingRows(),
    [130, 260, 260, 260, 460, 360, 720, 110],
  );
  await addDataSheet(
    workbook,
    "Grype Vulns",
    ["package", "installed", "type", "vulnerability", "related", "severity", "fixed_in", "epss", "risk", "description", "urls"],
    await buildGrypeRows(),
    [300, 140, 120, 180, 260, 100, 180, 100, 100, 520, 520],
  );
  await addDataSheet(
    workbook,
    "SBOM",
    ["name", "version", "type", "language", "metadata_type", "licenses", "purl", "locations"],
    await buildSbomRows(),
    [330, 170, 120, 110, 190, 170, 480, 300],
  );
  await addTsvSheet(workbook, "Malware Indicators", files.malware, [220, 100, 380, 160, 760]);
  await addLineSheet(workbook, "Dynamic Libraries", files.dynamicLibraries, ["library"], (line) => [line], [260]);
  await addLineSheet(workbook, "Enterprise Symbols", files.enterpriseSymbols, ["address", "type", "symbol"], parseSymbolLine, [160, 80, 720]);
  await addLineSheet(workbook, "High Value Symbols", files.highValueSymbols, ["address", "type", "symbol"], parseSymbolLine, [160, 80, 760]);
  await addLineSheet(workbook, "ELF Sections", files.readelfSections, ["line_no", "line"], parseReadelfLine, [90, 900]);
  await addLineSheet(workbook, "ELF Program Headers", files.readelfProgramHeaders, ["line_no", "line"], parseReadelfLine, [90, 900]);
  await addLineSheet(workbook, "ELF Dynamic", files.readelfDynamic, ["line_no", "line"], parseReadelfLine, [90, 900]);
  await addLineSheet(workbook, "ELF Imports", files.rzImports, ["line_no", "line"], parseReadelfLine, [90, 900]);
  await addLineSheet(workbook, "ELF Dyn Symbols", files.readelfDynsyms, ["line_no", "line"], parseReadelfLine, [90, 900]);
  await addLineSheet(workbook, "ELF Symbols", files.readelfSymbols, ["line_no", "line"], parseReadelfLine, [90, 900]);
  await addLineSheet(
    workbook,
    "Raw Strings",
    files.rawStrings,
    ["offset", "string_preview", "original_length", "sha256", "truncated"],
    parseStringsLine,
    [120, 900, 140, 520, 100],
  );
  await addDataSheet(workbook, "Artifact Index", ["artifact", "absolute_path", "size_bytes"], await buildArtifactIndexRows(), [260, 900, 140]);

  const overview = await workbook.inspect({
    kind: "sheet",
    include: "id,name",
    maxChars: 5000,
  });
  console.log(overview.ndjson);

  const summaryCheck = await workbook.inspect({
    kind: "table",
    range: "Summary!A1:B20",
    include: "values",
    tableMaxRows: 20,
    tableMaxCols: 2,
    maxChars: 5000,
  });
  console.log(summaryCheck.ndjson);

  const errors = await workbook.inspect({
    kind: "match",
    searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A",
    options: { useRegex: true, maxResults: 100 },
    summary: "final formula error scan",
    maxChars: 2000,
  });
  console.log(errors.ndjson);

  await workbook.render({ sheetName: "Summary", range: "A1:B20", scale: 1, format: "png" });
  await workbook.render({ sheetName: "API Routes", range: "A1:F25", scale: 1, format: "png" });
  await workbook.render({ sheetName: "Grype Vulns", range: "A1:K25", scale: 1, format: "png" });
  await workbook.render({ sheetName: "Raw Strings", range: "A1:E25", scale: 1, format: "png" });

  await fs.mkdir(outputDir, { recursive: true });
  const output = await SpreadsheetFile.exportXlsx(workbook);
  await output.save(outputPath);
  console.log(`saved ${outputPath}`);
}

await main();
