"use client";

import { createStore, createSelectedIdStorage } from "@/lib/serviceUtils";
import { schemaApi, type BackendDbSchemaItem, type ListDbSchemasResponse, type CreateDbSchema, type UpdateDbSchema } from "./api";

export type SchemaOption = { value: string; name: string };
type SchemaState = { schemas: BackendDbSchemaItem[]; options: SchemaOption[]; selectedId: string | null; loading: boolean; error?: string };

const SCHEMA_SELECTED_KEY = "SELECTED_SCHEMA_ID";
const schemaStore = createStore<SchemaState>({ schemas: [], options: [], selectedId: null, loading: false });
const { read: readSavedSchema, save: saveSchema } = createSelectedIdStorage(SCHEMA_SELECTED_KEY);

function toOptions(items: BackendDbSchemaItem[]): SchemaOption[] {
    return items.map(it => ({ value: String(it.id), name: it.schema_name || String(it.id) }));
}

export const schemaService = {
    subscribe(fn: () => void) { return schemaStore.subscribe(fn); },
    getState(): Readonly<SchemaState> { return schemaStore.getState(); },
    getOptions(): SchemaOption[] { return schemaStore.getState().options; },
    getSelectedId(): string | null { return schemaStore.getState().selectedId; },

    async init() {
        schemaStore.setState({ loading: true, error: undefined });
        try {
            const data = await schemaApi.list();
            const items = Array.isArray(data.schemas) ? data.schemas : [];
            const options = toOptions(items);
            schemaStore.setState({ schemas: items, options });
            let selected: string | null = null;
            const activeFromList = typeof data.active_schema_id === "number" && data.active_schema_id > 0 ? String(data.active_schema_id) : null;
            if (activeFromList) {
                selected = activeFromList;
            } else {
                try { const active = await schemaApi.getActive(); selected = active ? String(active.id) : null; } catch { }
            }
            if (!selected) selected = readSavedSchema();
            if (selected && !options.find(o => o.value === selected)) selected = null;
            if (!selected) selected = options[0]?.value ?? null;
            schemaStore.setState({ selectedId: selected });
            if (selected) saveSchema(selected);
        } catch (e) {
            schemaStore.setState({ error: e instanceof Error ? e.message : String(e) });
        } finally { schemaStore.setState({ loading: false }); }
    },

    async refresh() {
        schemaStore.setState({ loading: true, error: undefined });
        try {
            const data = await schemaApi.list();
            const items = Array.isArray(data.schemas) ? data.schemas : [];
            const options = toOptions(items);
            const activeId = typeof data.active_schema_id === "number" && data.active_schema_id > 0 ? String(data.active_schema_id) : null;
            let selected = activeId;
            if (!selected) {
                const current = schemaStore.getState().selectedId;
                selected = current && options.find(o => o.value === current) ? current : (options[0]?.value ?? null);
            }
            schemaStore.setState({ schemas: items, options, selectedId: selected });
            if (selected) saveSchema(selected); else saveSchema(null);
        } catch (e) {
            schemaStore.setState({ error: e instanceof Error ? e.message : String(e) });
        } finally { schemaStore.setState({ loading: false }); }
    },

    async select(id: string) {
        const numericId = Number(id);
        await schemaApi.setActive(numericId);
        if (schemaStore.getState().options.find(o => o.value === String(numericId))) {
            schemaStore.setState({ selectedId: String(numericId) });
            saveSchema(String(numericId));
        } else {
            await this.refresh();
        }
    },

    async getActive() { return schemaApi.getActive(); },
    async list(params?: { skip?: number; limit?: number }) { return schemaApi.list(params); },
    async get(schemaId: number | string) { return schemaApi.get(schemaId); },
    async create(payload: CreateDbSchema) { const created = await schemaApi.create(payload); await this.refresh(); return created; },
    async update(schemaId: number | string, payload: UpdateDbSchema, method: "PUT" | "PATCH" = "PUT") {
        const updated = await schemaApi.update(schemaId, payload, method);
        const prev = schemaStore.getState();
        const idStr = String(schemaId);
        const schemas = prev.schemas.map(s => String(s.id) === idStr ? { ...s, ...updated } : s);
        const options = prev.options.map(o => o.value === idStr ? { ...o, name: (updated as BackendDbSchemaItem).schema_name || o.name } : o);
        schemaStore.setState({ schemas, options });
        return updated;
    },
    async remove(schemaId: number | string) {
        await schemaApi.remove(schemaId);
        const idStr = String(schemaId);
        const prev = schemaStore.getState();
        const schemas = prev.schemas.filter(s => String(s.id) !== idStr);
        const options = prev.options.filter(o => o.value !== idStr);
        let selected = prev.selectedId;
        if (selected === idStr) selected = options[0]?.value ?? null;
        schemaStore.setState({ schemas, options, selectedId: selected });
        if (selected) saveSchema(selected); else saveSchema(null);
    },
};

export type { BackendDbSchemaItem, ListDbSchemasResponse };
