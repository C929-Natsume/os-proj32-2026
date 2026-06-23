"use client";

import { createStore, createSelectedIdStorage } from "@/lib/serviceUtils";
import { databaseApi, type BackendDatabaseItem, type ListDatabasesResponse, type CreateDatabaseConnection, type UpdateDatabaseConnection } from "./api";

export type DatabaseOption = { value: string; name: string };
type DatabaseState = { databases: BackendDatabaseItem[]; options: DatabaseOption[]; selectedId: string | null; loading: boolean; error?: string };

const DB_SELECTED_KEY = "SELECTED_DB_ID";
const dbStore = createStore<DatabaseState>({ databases: [], options: [], selectedId: null, loading: false });
const { read: readSavedDb, save: saveDb } = createSelectedIdStorage(DB_SELECTED_KEY);

function toOptions(items: BackendDatabaseItem[]): DatabaseOption[] {
    return items.map(it => ({ value: String(it.id), name: it.database_name || String(it.id) }));
}

function applyDatabasesToStore(items: BackendDatabaseItem[], selectedOverride?: string | null) {
    const options = toOptions(items);
    let selected = selectedOverride ?? dbStore.getState().selectedId ?? null;
    if (!options.some(o => o.value === selected)) selected = options[0]?.value ?? null;
    dbStore.setState({ databases: items, options, selectedId: selected });
    saveDb(selected ?? null);
}

export const databaseService = {
    subscribe(fn: () => void) { return dbStore.subscribe(fn); },
    getState(): Readonly<DatabaseState> { return dbStore.getState(); },
    getOptions(): DatabaseOption[] { return dbStore.getState().options; },
    getSelectedId(): string | null { return dbStore.getState().selectedId; },

    async init() {
        dbStore.setState({ loading: true, error: undefined });
        try {
            const data = await databaseApi.list();
            const items = Array.isArray(data.databases) ? data.databases : [];
            const options = toOptions(items);
            dbStore.setState({ databases: items, options });
            let selected: string | null = null;
            const activeId = typeof data.active_connection_id === "number" && data.active_connection_id > 0 ? String(data.active_connection_id) : null;
            if (activeId) {
                selected = activeId;
            } else {
                try { const active = await databaseApi.getActive(); selected = active ? String(active.id) : null; } catch { /* ignore */ }
            }
            if (!selected) selected = readSavedDb();
            if (!options.some(o => o.value === selected)) selected = options[0]?.value ?? null;
            dbStore.setState({ selectedId: selected });
            saveDb(selected ?? null);
        } catch (e) {
            dbStore.setState({ error: e instanceof Error ? e.message : String(e) });
        } finally {
            dbStore.setState({ loading: false });
        }
    },

    async refresh() {
        dbStore.setState({ loading: true, error: undefined });
        try {
            const data = await databaseApi.list();
            const items = Array.isArray(data.databases) ? data.databases : [];
            const activeId = typeof (data as { active_connection_id?: number }).active_connection_id === "number" && (data as { active_connection_id?: number }).active_connection_id! > 0
                ? String((data as { active_connection_id?: number }).active_connection_id)
                : null;
            if (activeId) {
                applyDatabasesToStore(items, activeId);
            } else {
                const current = dbStore.getState().selectedId;
                const options = toOptions(items);
                const selected = current && options.some(o => o.value === current) ? current : (options[0]?.value ?? null);
                applyDatabasesToStore(items, selected);
            }
        } catch (e) {
            dbStore.setState({ error: e instanceof Error ? e.message : String(e) });
        } finally {
            dbStore.setState({ loading: false });
        }
    },

    async select(id: string) {
        await databaseApi.setActive(id);
        const found = dbStore.getState().options.some(o => o.value === String(id));
        dbStore.setState({ selectedId: found ? String(id) : dbStore.getState().selectedId });
        saveDb(found ? String(id) : null);
        if (!found) await this.refresh();
    },

    async getActive(): Promise<BackendDatabaseItem> { return databaseApi.getActive(); },
    async list(params?: { skip?: number; limit?: number; q?: string }): Promise<ListDatabasesResponse> { return databaseApi.list(params); },
    async get(connectionId: number | string): Promise<BackendDatabaseItem> { return databaseApi.get(connectionId); },
    async create(payload: CreateDatabaseConnection): Promise<BackendDatabaseItem> { const created = await databaseApi.create(payload); this.refresh().catch(() => void 0); return created; },
    async update(connectionId: number | string, payload: UpdateDatabaseConnection, method: "PUT" | "PATCH" = "PUT"): Promise<BackendDatabaseItem> {
        const updated = await databaseApi.update(connectionId, payload, method);
        const prev = dbStore.getState();
        const next = [...prev.databases];
        const idx = next.findIndex(d => String(d.id) === String(connectionId));
        if (idx >= 0) next[idx] = updated; else next.push(updated);
        applyDatabasesToStore(next);
        return updated;
    },
    async remove(connectionId: number | string): Promise<void> {
        await databaseApi.remove(connectionId);
        const idStr = String(connectionId);
        const prev = dbStore.getState();
        const next = prev.databases.filter(d => String(d.id) !== idStr);
        applyDatabasesToStore(next);
    },
};

export type { BackendDatabaseItem, ListDatabasesResponse };
