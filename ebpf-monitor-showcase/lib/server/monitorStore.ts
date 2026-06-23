import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';

type AnyRecord = Record<string, any>;

const DEFAULT_MONITOR_ROOT = '/mnt/e/os2026/ebpf-multi-agent-monitor';
const MONITOR_ROOT = process.env.MONITOR_PROJECT_ROOT || DEFAULT_MONITOR_ROOT;
const SQLITE_PATH = process.env.MONITOR_SQLITE_PATH || path.join(MONITOR_ROOT, 'logs', 'alerts', 'analysis.db');
const CONFIG_PATH = path.join(MONITOR_ROOT, 'src', 'config', 'app_config.yaml');
const SQLITE_URI = `file:${SQLITE_PATH}?mode=ro`;

function parseScalar(value: string): any {
  const trimmed = value.trim();
  if (!trimmed.length) return '';
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (trimmed === 'null') return null;
  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) return Number(trimmed);
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function parseSimpleYaml(text: string): AnyRecord {
  const root: AnyRecord = {};
  const stack: Array<{ indent: number; value: AnyRecord | any[] }> = [{ indent: -1, value: root }];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i += 1) {
    const rawLine = lines[i];
    const line = rawLine.replace(/\t/g, '    ');
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const indent = line.match(/^\s*/)?.[0].length || 0;
    const content = line.trim();
    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) stack.pop();
    const parent = stack[stack.length - 1].value;

    if (content.startsWith('- ')) {
      const itemText = content.slice(2);
      const item = itemText.includes(':') && !itemText.startsWith('http') ? {} as AnyRecord : parseScalar(itemText);
      if (Array.isArray(parent)) {
        parent.push(item);
        if (typeof item === 'object' && item !== null && !Array.isArray(item)) {
          stack.push({ indent, value: item });
        }
      }
      continue;
    }

    const colon = content.indexOf(':');
    if (colon === -1 || Array.isArray(parent)) continue;
    const key = content.slice(0, colon).trim();
    const rest = content.slice(colon + 1).trim();
    if (!rest) {
      const nextTrim = (lines[i + 1] || '').trim();
      const container: AnyRecord | any[] = nextTrim.startsWith('- ') ? [] : {};
      parent[key] = container;
      stack.push({ indent, value: container });
    } else {
      parent[key] = parseScalar(rest);
    }
  }

  return root;
}

let cachedConfig: AnyRecord | null = null;
let lastConfigMtime = 0;

export function getMonitorRoot() {
  return MONITOR_ROOT;
}

export function getSqlitePath() {
  return SQLITE_PATH;
}

export function loadAppConfig(): AnyRecord {
  try {
    const stat = fs.statSync(CONFIG_PATH);
    if (cachedConfig && stat.mtimeMs === lastConfigMtime) return cachedConfig;
    const text = fs.readFileSync(CONFIG_PATH, 'utf8');
    const parsed = parseSimpleYaml(text);
    cachedConfig = parsed;
    lastConfigMtime = stat.mtimeMs;
    return parsed;
  } catch {
    return cachedConfig || {};
  }
}

function parseJsonMaybe(value: any) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'object') return value;
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function safeReadJsonColumns(row: AnyRecord, keys: string[]) {
  const out: AnyRecord = { ...row };
  for (const key of keys) {
    if (key in out) out[key] = parseJsonMaybe(out[key]);
  }
  return out;
}

function tryExec(args: string[]) {
  return execFileSync('sqlite3', args, { encoding: 'utf8' }).trim();
}

function runSql<T = AnyRecord>(sql: string, params: any[] = []): T[] {
  const preparedSql = sql.replace(/\?/g, () => {
    const value = params.shift();
    if (value === null || value === undefined) return 'NULL';
    if (typeof value === 'number') return String(value);
    return `'${String(value).replace(/'/g, "''")}'`;
  });

  let output = '';
  try {
    output = tryExec(['-json', SQLITE_URI, preparedSql]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes('database is locked')) throw error;
    output = tryExec(['-readonly', '-json', SQLITE_PATH, preparedSql]);
  }

  if (!output) return [];
  return JSON.parse(output) as T[];
}

export function rows<T = AnyRecord>(sql: string, params: any[] = []): T[] {
  return runSql<T>(sql, [...params]);
}

export function row<T = AnyRecord>(sql: string, params: any[] = []): T | undefined {
  return runSql<T>(sql, [...params])[0];
}

export function count(table: string): number {
  const r = row<{ c: number }>(`select count(*) as c from ${table}`);
  return Number(r?.c || 0);
}

export function readJsonRow<T = AnyRecord>(sql: string, params: any[] = [], jsonKeys: string[] = []): T | undefined {
  const data = row<AnyRecord>(sql, params);
  if (!data) return undefined;
  return safeReadJsonColumns(data, jsonKeys) as T;
}

export function readJsonRows<T = AnyRecord>(sql: string, params: any[] = [], jsonKeys: string[] = []): T[] {
  return rows<AnyRecord>(sql, params).map((r) => safeReadJsonColumns(r, jsonKeys) as T);
}
