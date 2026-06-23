import crypto from 'crypto';
import { count, getMonitorRoot, getSqlitePath, loadAppConfig, readJsonRows, row, rows } from './monitorStore';
import {
  createDatabase,
  createModel,
  createSchema,
  deleteDatabase,
  deleteModel,
  deleteSchema,
  listModelsStore,
  setActiveDatabase,
  setActiveModel,
  setActiveSchema,
  updateDatabase,
  updateModel,
  updateSchema,
} from './showcaseConfig';

type AnyRecord = Record<string, any>;

function normalizeString(v: any, fallback = '') {
  return typeof v === 'string' && v.trim() ? v : fallback;
}

function inferClass(rule = '', severity = '') {
  const r = rule.toUpperCase();
  const s = severity.toUpperCase();
  if (s === 'HIGH' || /SENSITIVE|DANGEROUS|WORKSPACE|UNUSUAL|INJECTION|SSL/.test(r)) return 'BLACK';
  if (s === 'MEDIUM') return 'GRAY';
  return 'WHITE';
}

function inferDecision(cls: string) {
  if (cls === 'BLACK') return 'ALERT';
  if (cls === 'GRAY') return 'CORRELATE';
  return 'ALLOW';
}

function inferRisk(cls: string) {
  if (cls === 'BLACK') return 'HIGH';
  if (cls === 'GRAY') return 'MEDIUM';
  return 'LOW';
}

function buildReasoning(req: AnyRecord) {
  const comm = normalizeString(req.comm, 'unknown');
  const rule = normalizeString(req.rule, 'UNKNOWN_RULE');
  const object = normalizeString(req.object, '-');
  const reason = normalizeString(req.reason, '无附加说明');
  return `进程 ${comm} 触发 ${rule}，访问对象 ${object}，原因：${reason}`;
}

function buildResult(req: AnyRecord) {
  const cls = inferClass(req.rule, req.severity);
  const decision = inferDecision(cls);
  const risk = inferRisk(cls);
  return {
    type: 'result',
    status: cls === 'BLACK' ? 'blocked' : cls === 'GRAY' ? 'review' : 'allowed',
    class: cls,
    decision,
    risk_level: risk,
    summary: `${normalizeString(req.comm, '进程')} ${req.rule || 'UNKNOWN_RULE'} 告警已分析`,
    reasoning: buildReasoning(req),
    evidence: Array.isArray(req.evidence) ? req.evidence : [],
    suggested_action: decision,
  };
}

function toModelItem(item: AnyRecord) {
  return {
    id: Number(item.id),
    model_name: normalizeString(item.model_name, item.model || `model-${item.id}`),
    model: normalizeString(item.model, item.model_name || `model-${item.id}`),
    base_url: normalizeString(item.base_url),
    api_key: normalizeString(item.api_key),
    model_description: normalizeString(item.model_description),
    model_avatar_url: normalizeString(item.model_avatar_url),
    created_at: normalizeString(item.created_at, new Date().toISOString()),
    updated_at: normalizeString(item.updated_at, new Date().toISOString()),
  };
}

function toDatabaseItem(item: AnyRecord) {
  return {
    id: Number(item.id),
    database_name: normalizeString(item.database_name, `database-${item.id}`),
    database_uri: normalizeString(item.database_uri, getSqlitePath()),
    database_type: normalizeString(item.database_type, 'sqlite'),
    database_description: normalizeString(item.database_description),
    created_at: normalizeString(item.created_at, new Date().toISOString()),
    updated_at: normalizeString(item.updated_at, new Date().toISOString()),
  };
}

function toSchemaItem(item: AnyRecord) {
  return {
    id: Number(item.id),
    schema_name: normalizeString(item.schema_name, `schema-${item.id}`),
    schema_content: normalizeString(item.schema_content, 'events, anomalies, audit_results'),
    created_at: normalizeString(item.created_at, new Date().toISOString()),
    updated_at: normalizeString(item.updated_at, new Date().toISOString()),
    user_id: Number(item.user_id || 1),
  };
}

export function getHealth() {
  const cfg = loadAppConfig();
  return {
    status: 'ok',
    monitor_root: getMonitorRoot(),
    sqlite_path: getSqlitePath(),
    llm: cfg.llm || {},
    counts: {
      events: count('events'),
      anomalies: count('anomalies'),
      audit_results: count('audit_results'),
    },
  };
}

export function listModels() {
  const store = listModelsStore();
  return { models: store.models.map(toModelItem), total: store.models.length, skip: 0, limit: store.models.length || 100, active_connection_id: store.active_model_id };
}

export function getModel(id: number) {
  return listModelsStore().models.find((m) => m.id === id) || null;
}

export function postModel(payload: AnyRecord) { return toModelItem(createModel(payload)); }
export function putModel(id: number, payload: AnyRecord) { const updated = updateModel(id, payload); return updated ? toModelItem(updated) : null; }
export function removeModel(id: number) { return deleteModel(id); }
export function activateModel(id: number) { return setActiveModel(id); }

export function listDatabases() {
  const store = listModelsStore();
  return { databases: store.databases.map(toDatabaseItem), total: store.databases.length, skip: 0, limit: store.databases.length || 100, active_connection_id: store.active_database_id };
}

export function getDatabase(id: number) { return listModelsStore().databases.find((d) => d.id === id) || null; }
export function postDatabase(payload: AnyRecord) { return toDatabaseItem(createDatabase(payload)); }
export function putDatabase(id: number, payload: AnyRecord) { const updated = updateDatabase(id, payload); return updated ? toDatabaseItem(updated) : null; }
export function removeDatabase(id: number) { return deleteDatabase(id); }
export function activateDatabase(id: number) { return setActiveDatabase(id); }

export function listSchemas() {
  const store = listModelsStore();
  return { schemas: store.schemas.map(toSchemaItem), total: store.schemas.length, skip: 0, limit: store.schemas.length || 100, active_schema_id: store.active_schema_id };
}

export function getSchema(id: number) { return listModelsStore().schemas.find((s) => s.id === id) || null; }
export function postSchema(payload: AnyRecord) { return toSchemaItem(createSchema(payload)); }
export function putSchema(id: number, payload: AnyRecord) { const updated = updateSchema(id, payload); return updated ? toSchemaItem(updated) : null; }
export function removeSchema(id: number) { return deleteSchema(id); }
export function activateSchema(id: number) { return setActiveSchema(id); }

export function getOverview() {
  const anomalyRows = rows('select rule, severity, comm, agent_id from anomalies order by id desc limit 500');
  const eventRows = rows('select comm, agent_id from events order by id desc limit 500');
  const severity: Record<string, number> = {};
  const ruleCounts: Record<string, number> = {};
  const agentCounts: Record<string, number> = {};
  for (const a of anomalyRows) {
    severity[a.severity || 'UNKNOWN'] = (severity[a.severity || 'UNKNOWN'] || 0) + 1;
    ruleCounts[a.rule || 'UNKNOWN'] = (ruleCounts[a.rule || 'UNKNOWN'] || 0) + 1;
  }
  for (const e of eventRows) {
    const key = e.agent_id || e.comm || 'unknown';
    agentCounts[key] = (agentCounts[key] || 0) + 1;
  }
  return {
    metrics: {
      events: count('events'),
      anomalies: count('anomalies'),
      audit_results: count('audit_results'),
      agents_observed: Object.keys(agentCounts).length,
    },
    severity_breakdown: severity,
    top_rules: Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([rule, count]) => ({ rule, count })),
    top_agents: Object.entries(agentCounts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([agent, count]) => ({ agent, count })),
  };
}

export function getEvents(limit = 50) {
  return readJsonRows('select id, timestamp_ns, event_type, pid, ppid, uid, comm, agent_id, main_pid, object, payload_json, created_at_ns from events order by id desc limit ?', [limit], ['payload_json']).map((r: AnyRecord) => ({ ...r, payload: r.payload_json, payload_json: undefined }));
}

export function getAnomalies(limit = 50) {
  return readJsonRows('select id, anomaly_id, timestamp_ns, pid, tid, comm, agent_id, rule, severity, object, reason, details_json, created_at_ns from anomalies order by id desc limit ?', [limit], ['details_json']).map((r: AnyRecord) => ({ ...r, details: r.details_json, details_json: undefined }));
}

export function getAuditResults(limit = 50) {
  return readJsonRows('select id, timestamp_ns, pid, tid, comm, agent_id, rule, severity, request_json, result_json, created_at_ns from audit_results order by id desc limit ?', [limit], ['request_json', 'result_json']).map((r: AnyRecord) => ({ ...r, request: r.request_json, result: r.result_json, request_json: undefined, result_json: undefined }));
}

export function handleAuthRegister(body: AnyRecord) {
  return { access_token: crypto.randomUUID(), refresh_token: crypto.randomUUID(), token_type: 'bearer', user_id: 1, user_name: body?.name || 'Default' };
}

export function handleAuthLogin(body: AnyRecord) {
  return { access_token: crypto.randomUUID(), refresh_token: crypto.randomUUID(), token_type: 'bearer', user_id: 1, user_name: body?.email?.split('@')?.[0] || 'Default' };
}

export function summarizeAuditRequest(req: AnyRecord) {
  const result = buildResult(req);
  return {
    req_id: req.req_id ?? 0,
    timestamp_ns: req.timestamp_ns ?? Date.now() * 1e6,
    pid: req.pid ?? 0,
    tid: req.tid ?? req.pid ?? 0,
    comm: normalizeString(req.comm, 'unknown'),
    agent_id: normalizeString(req.agent_id, `agent_${req.pid || 0}`),
    rule: normalizeString(req.rule, 'UNKNOWN_RULE'),
    severity: normalizeString(req.severity, 'MEDIUM'),
    object: normalizeString(req.object, '-'),
    reason: normalizeString(req.reason, '无附加说明'),
    evidence: Array.isArray(req.evidence) ? req.evidence : [],
    class: result.class,
    decision: result.decision,
    risk_level: result.risk_level,
    summary: result.summary,
    reasoning: result.reasoning,
    suggested_action: result.suggested_action,
    status: result.status,
  };
}

export function findLatestAnomaliesByQuery(query: string, limit = 5) {
  const normalized = query.toLowerCase();
  const all = getAnomalies(100);
  const matches = all.filter((item: AnyRecord) => {
    const haystack = [item.rule, item.severity, item.comm, item.agent_id, item.object, item.reason].join(' ').toLowerCase();
    return haystack.includes(normalized) || normalized.split(/\s+/).some((token) => token && haystack.includes(token));
  });
  return (matches.length ? matches : all).slice(0, limit);
}

export function findRelatedAudit(rule: string, pid?: number) {
  const audits = getAuditResults(100);
  return audits.find((a: AnyRecord) => a.rule === rule && (!pid || Number(a.pid) === Number(pid))) || audits.find((a: AnyRecord) => a.rule === rule) || null;
}
