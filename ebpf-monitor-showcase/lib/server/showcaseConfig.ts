import fs from 'fs';
import path from 'path';
import { getMonitorRoot, getSqlitePath, loadAppConfig } from './monitorStore';

type ModelItem = {
  id: number;
  model_name: string;
  model: string;
  base_url: string;
  api_key: string;
  model_description: string;
  model_avatar_url: string;
  created_at: string;
  updated_at: string;
};

type DatabaseItem = {
  id: number;
  database_name: string;
  database_uri: string;
  database_type: string;
  database_description: string;
  created_at: string;
  updated_at: string;
};

type SchemaItem = {
  id: number;
  schema_name: string;
  schema_content: string;
  created_at: string;
  updated_at: string;
  user_id: number;
};

type Store = {
  models: ModelItem[];
  active_model_id: number;
  databases: DatabaseItem[];
  active_database_id: number;
  schemas: SchemaItem[];
  active_schema_id: number;
};

const STORE_DIR = path.join(process.cwd(), '.showcase');
const STORE_PATH = path.join(STORE_DIR, 'config.json');

function nowIso() {
  return new Date().toISOString();
}

function defaultStore(): Store {
  const llm = loadAppConfig().llm || {};
  const ts = nowIso();
  return {
    models: [
      {
        id: 1,
        model_name: String(llm.model || 'deepseek-chat'),
        model: String(llm.model || 'deepseek-chat'),
        base_url: String(llm.endpoint || 'https://api.deepseek.com/chat/completions'),
        api_key: '',
        model_description: '主监控项目当前启用的审计模型',
        model_avatar_url: '',
        created_at: ts,
        updated_at: ts,
      },
      {
        id: 2,
        model_name: 'qwen-plus',
        model: 'qwen-plus',
        base_url: '',
        api_key: '',
        model_description: '展示用参考模型',
        model_avatar_url: '',
        created_at: ts,
        updated_at: ts,
      },
    ],
    active_model_id: 1,
    databases: [
      {
        id: 1,
        database_name: '分析库',
        database_uri: getSqlitePath(),
        database_type: 'sqlite',
        database_description: `真实告警分析库，来源于 ${getMonitorRoot()}`,
        created_at: ts,
        updated_at: ts,
      },
    ],
    active_database_id: 1,
    schemas: [
      {
        id: 1,
        schema_name: '监控审计视图',
        schema_content: 'events, anomalies, audit_results',
        created_at: ts,
        updated_at: ts,
        user_id: 1,
      },
    ],
    active_schema_id: 1,
  };
}

function ensureStore() {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
  if (!fs.existsSync(STORE_PATH)) {
    fs.writeFileSync(STORE_PATH, JSON.stringify(defaultStore(), null, 2), 'utf8');
  }
}

export function readStore(): Store {
  ensureStore();
  return JSON.parse(fs.readFileSync(STORE_PATH, 'utf8')) as Store;
}

export function writeStore(next: Store) {
  ensureStore();
  fs.writeFileSync(STORE_PATH, JSON.stringify(next, null, 2), 'utf8');
}

function nextId(items: Array<{ id: number }>) {
  return items.length ? Math.max(...items.map((i) => i.id)) + 1 : 1;
}

export function listModelsStore() {
  return readStore();
}

export function createModel(payload: Partial<ModelItem>) {
  const store = readStore();
  const ts = nowIso();
  const item: ModelItem = {
    id: nextId(store.models),
    model_name: payload.model_name || payload.model || `model-${store.models.length + 1}`,
    model: payload.model || payload.model_name || `model-${store.models.length + 1}`,
    base_url: payload.base_url || '',
    api_key: payload.api_key || '',
    model_description: payload.model_description || '',
    model_avatar_url: payload.model_avatar_url || '',
    created_at: ts,
    updated_at: ts,
  };
  store.models.push(item);
  if (!store.active_model_id) store.active_model_id = item.id;
  writeStore(store);
  return item;
}

export function updateModel(id: number, payload: Partial<ModelItem>) {
  const store = readStore();
  const idx = store.models.findIndex((i) => i.id === id);
  if (idx === -1) return null;
  store.models[idx] = { ...store.models[idx], ...payload, id, updated_at: nowIso() };
  writeStore(store);
  return store.models[idx];
}

export function deleteModel(id: number) {
  const store = readStore();
  const idx = store.models.findIndex((i) => i.id === id);
  if (idx === -1) return false;
  store.models.splice(idx, 1);
  if (store.active_model_id === id) store.active_model_id = store.models[0]?.id || 0;
  writeStore(store);
  return true;
}

export function setActiveModel(id: number) {
  const store = readStore();
  if (!store.models.find((i) => i.id === id)) return false;
  store.active_model_id = id;
  writeStore(store);
  return true;
}

export function createDatabase(payload: Partial<DatabaseItem>) {
  const store = readStore();
  const ts = nowIso();
  const item: DatabaseItem = {
    id: nextId(store.databases),
    database_name: payload.database_name || `database-${store.databases.length + 1}`,
    database_uri: payload.database_uri || getSqlitePath(),
    database_type: payload.database_type || 'sqlite',
    database_description: payload.database_description || '',
    created_at: ts,
    updated_at: ts,
  };
  store.databases.push(item);
  if (!store.active_database_id) store.active_database_id = item.id;
  writeStore(store);
  return item;
}

export function updateDatabase(id: number, payload: Partial<DatabaseItem>) {
  const store = readStore();
  const idx = store.databases.findIndex((i) => i.id === id);
  if (idx === -1) return null;
  store.databases[idx] = { ...store.databases[idx], ...payload, id, updated_at: nowIso() };
  writeStore(store);
  return store.databases[idx];
}

export function deleteDatabase(id: number) {
  const store = readStore();
  const idx = store.databases.findIndex((i) => i.id === id);
  if (idx === -1) return false;
  store.databases.splice(idx, 1);
  if (store.active_database_id === id) store.active_database_id = store.databases[0]?.id || 0;
  writeStore(store);
  return true;
}

export function setActiveDatabase(id: number) {
  const store = readStore();
  if (!store.databases.find((i) => i.id === id)) return false;
  store.active_database_id = id;
  writeStore(store);
  return true;
}

export function createSchema(payload: Partial<SchemaItem>) {
  const store = readStore();
  const ts = nowIso();
  const item: SchemaItem = {
    id: nextId(store.schemas),
    schema_name: payload.schema_name || `schema-${store.schemas.length + 1}`,
    schema_content: payload.schema_content || 'events, anomalies, audit_results',
    created_at: ts,
    updated_at: ts,
    user_id: 1,
  };
  store.schemas.push(item);
  if (!store.active_schema_id) store.active_schema_id = item.id;
  writeStore(store);
  return item;
}

export function updateSchema(id: number, payload: Partial<SchemaItem>) {
  const store = readStore();
  const idx = store.schemas.findIndex((i) => i.id === id);
  if (idx === -1) return null;
  store.schemas[idx] = { ...store.schemas[idx], ...payload, id, updated_at: nowIso() };
  writeStore(store);
  return store.schemas[idx];
}

export function deleteSchema(id: number) {
  const store = readStore();
  const idx = store.schemas.findIndex((i) => i.id === id);
  if (idx === -1) return false;
  store.schemas.splice(idx, 1);
  if (store.active_schema_id === id) store.active_schema_id = store.schemas[0]?.id || 0;
  writeStore(store);
  return true;
}

export function setActiveSchema(id: number) {
  const store = readStore();
  if (!store.schemas.find((i) => i.id === id)) return false;
  store.active_schema_id = id;
  writeStore(store);
  return true;
}
