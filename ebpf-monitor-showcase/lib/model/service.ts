"use client";

import { createStore, createSelectedIdStorage } from "@/lib/serviceUtils";
import { modelApi, type BackendModelItem, type ListModelsResponse, type CreateModelConnection, type UpdateModelConnection, type SetActiveModelConnectionResponse } from "./api";

export type ModelOption = { value: string; name: string; iconKey: string };
type ModelState = { models: BackendModelItem[]; options: ModelOption[]; selectedId: string | null; loading: boolean; error?: string };

const LS_SELECTED_KEY = "SELECTED_MODEL_ID";
const store = createStore<ModelState>({ models: [], options: [], selectedId: null, loading: false });
const selectedStorage = createSelectedIdStorage(LS_SELECTED_KEY);

function pickIconKey(modelOrName?: string): string {
    const key = (modelOrName || "").toLowerCase();
    if (/openai|gpt/.test(key)) return "openai";
    if (/deepseek/.test(key)) return "deepseek";
    if (/claude|anthropic/.test(key)) return "anthropic";
    if (/gemini|google/.test(key)) return "google";
    if (/llama|meta/.test(key)) return "meta";
    if (/mistral/.test(key)) return "mistral";
    if (/firefunction|fireworks/.test(key)) return "fireworks";
    if (/qwen/.test(key)) return "qwen";
    return "openai";
}

const toOptions = (models: BackendModelItem[]) => models.map(it => ({
    value: String(it.id),
    name: it.model_name || it.model || String(it.id),
    iconKey: pickIconKey(it.model),
}));

function applyModelsToStore(models: BackendModelItem[], selectedOverride?: string | null) {
    const options = toOptions(models);
    let selected = selectedOverride ?? store.getState().selectedId ?? null;
    if (!options.some(o => o.value === selected)) selected = options[0]?.value ?? null;
    store.setState({ models, options, selectedId: selected });
    selectedStorage.save(selected ?? null);
}

let initPromise: Promise<void> | null = null;

export const modelService = {
    subscribe(fn: () => void) { return store.subscribe(fn); },
    getState(): Readonly<ModelState> { return store.getState(); },
    getOptions(): ModelOption[] { return store.getState().options; },
    getSelectedId(): string | null { return store.getState().selectedId; },

    async init() {
        if (!initPromise) {
            initPromise = (async () => {
                store.setState({ loading: true, error: undefined });
                try {
                    const data = await modelApi.list();
                    const models = Array.isArray(data.models) ? data.models : [];
                    const options = toOptions(models);
                    store.setState({ models, options });
                    let selected: string | null = null;
                    const activeId = typeof data.active_connection_id === "number" && data.active_connection_id > 0 ? String(data.active_connection_id) : null;
                    if (activeId) {
                        selected = activeId;
                    } else {
                        try { const active = await modelApi.getActive(); selected = active ? String(active.id) : null; } catch { selected = null; }
                    }
                    if (!selected) selected = selectedStorage.read();
                    if (!options.some(o => o.value === selected)) selected = options[0]?.value ?? null;
                    store.setState({ selectedId: selected });
                    selectedStorage.save(selected ?? null);
                } catch (e) {
                    store.setState({ models: [], options: [], selectedId: null, error: e instanceof Error ? e.message : String(e) });
                } finally {
                    store.setState({ loading: false });
                }
            })();
        }
        return initPromise;
    },

    async refresh() {
        store.setState({ loading: true, error: undefined });
        try {
            const data = await modelApi.list();
            const models = Array.isArray(data.models) ? data.models : [];
            const activeId = typeof data.active_connection_id === "number" && data.active_connection_id > 0 ? String(data.active_connection_id) : null;
            if (activeId) {
                applyModelsToStore(models, activeId);
            } else {
                const current = store.getState().selectedId;
                const options = toOptions(models);
                const selected = current && options.some(o => o.value === current) ? current : (options[0]?.value ?? null);
                applyModelsToStore(models, selected);
            }
        } catch (e) {
            store.setState({ error: e instanceof Error ? e.message : String(e) });
        } finally {
            store.setState({ loading: false });
        }
    },

    async select(id: string) {
        await modelApi.setActive(id);
        const found = store.getState().options.some(o => o.value === String(id));
        store.setState({ selectedId: found ? String(id) : store.getState().selectedId });
        selectedStorage.save(found ? String(id) : null);
        if (!found) await this.refresh();
    },

    async getActive(): Promise<BackendModelItem> { return modelApi.getActive(); },
    async list(params?: { skip?: number; limit?: number; model?: string }): Promise<ListModelsResponse> { return modelApi.list(params); },
    async get(connectionId: number | string): Promise<BackendModelItem> { return modelApi.get(connectionId); },
    async create(payload: CreateModelConnection): Promise<BackendModelItem> { const created = await modelApi.create(payload); this.refresh().catch(() => void 0); return created; },
    async setActive(connectionId: number | string): Promise<SetActiveModelConnectionResponse> { return modelApi.setActive(connectionId); },
    async update(connectionId: string, payload: UpdateModelConnection, method: "PUT" | "PATCH" = "PUT"): Promise<BackendModelItem> {
        const updated = await modelApi.update(connectionId, payload, method);
        const prev = store.getState();
        const nextModels = [...prev.models];
        const idx = nextModels.findIndex(m => String(m.id) === String(connectionId));
        if (idx >= 0) nextModels[idx] = updated; else nextModels.push(updated);
        applyModelsToStore(nextModels);
        return updated;
    },
    async remove(connectionId: number | string): Promise<void> {
        await modelApi.remove(connectionId);
        const idStr = String(connectionId);
        const prev = store.getState();
        const nextModels = prev.models.filter(m => String(m.id) !== idStr);
        applyModelsToStore(nextModels);
    },
};

export type { BackendModelItem, ListModelsResponse };
