import { buildHeaders } from "@/lib/serviceUtils";
import { fetchWithAuth } from "@/lib/auth";
import { HttpError, NotFoundError, ValidationError } from "@/lib/errors";

const BASE_URL = process.env.NEXT_PUBLIC_SQLOPT_SERVICE_URL || "";

function apiUrl(path: string) {
    const origin = typeof window !== "undefined" ? window.location.origin : "http://localhost";
    return new URL(path, BASE_URL || origin);
}

export type CreateModelConnection = Record<string, unknown>;
export type UpdateModelConnection = Record<string, unknown>;

export interface BackendModelItem {
    id: number;
    model_name: string;
    model: string;
    base_url: string;
    api_key: string;
    model_description: string;
    model_avatar_url: string;
    created_at: string;
    updated_at: string;
}

export interface ListModelsResponse {
    models: BackendModelItem[];
    total: number;
    skip: number;
    limit: number;
    has_more?: boolean;
    active_connection_id?: number;
}

export interface SetActiveModelConnectionResponse { message: string }

export const modelApi = {
    async getActive(): Promise<BackendModelItem> {
        const url = apiUrl("/api/models/active");
        const resp = await fetchWithAuth(url.toString(), { method: "GET", headers: buildHeaders(false), redirect: "follow" });
        if (!resp.ok) {
            if (resp.status === 404) throw new NotFoundError("未找到活跃模型连接");
            throw new Error(`getActive failed: ${resp.status}`);
        }
        return (await resp.json()) as BackendModelItem;
    },

    async list(params?: { skip?: number; limit?: number; model?: string }): Promise<ListModelsResponse> {
        const url = apiUrl("/api/models/");
        const skip = params?.skip ?? 0;
        const limit = params?.limit ?? 100;
        url.searchParams.set("skip", String(skip));
        url.searchParams.set("limit", String(limit));
        if (params?.model !== undefined) url.searchParams.set("model", String(params.model));
        const resp = await fetchWithAuth(url.toString(), { method: "GET", headers: buildHeaders(false), redirect: "follow" });
        if (!resp.ok) throw new Error(`list failed: ${resp.status}`);
        const data = await resp.json();
        if (!data || !Array.isArray(data.models)) return { models: [], total: 0, skip, limit };
        return data as ListModelsResponse;
    },

    async create(payload: CreateModelConnection): Promise<BackendModelItem> {
        const url = apiUrl("/api/models/");
        const resp = await fetchWithAuth(url.toString(), { method: "POST", headers: buildHeaders(true), body: JSON.stringify(payload), redirect: "follow" });
        if (!resp.ok) throw new Error(`create failed: ${resp.status}`);
        return (await resp.json()) as BackendModelItem;
    },

    async setActive(connectionId: number | string): Promise<SetActiveModelConnectionResponse> {
        const url = apiUrl("/api/models/active");
        const resp = await fetchWithAuth(url.toString(), { method: "POST", headers: buildHeaders(true), body: JSON.stringify({ connection_id: Number(connectionId) }), redirect: "follow" });
        if (resp.ok) { try { return await resp.json(); } catch { return { message: "OK" }; } }
        let payload: unknown = undefined;
        try { const ct = resp.headers.get("content-type") || ""; payload = ct.includes("application/json") ? await resp.json() : await resp.text(); } catch { }
        if (resp.status === 404) throw new NotFoundError("记录不存在", payload);
        if (resp.status === 422) throw new ValidationError("参数错误", payload);
        throw new HttpError(`setActive failed: ${resp.status}`, resp.status, payload);
    },

    async get(connectionId: number | string): Promise<BackendModelItem> {
        const url = apiUrl(`/api/models/${encodeURIComponent(String(connectionId))}`);
        const resp = await fetchWithAuth(url.toString(), { method: "GET", headers: buildHeaders(false), redirect: "follow" });
        if (!resp.ok) throw new Error(`get failed: ${resp.status}`);
        return (await resp.json()) as BackendModelItem;
    },

    async update(connectionId: string, payload: UpdateModelConnection, method: "PUT" | "PATCH" = "PUT"): Promise<BackendModelItem> {
        const url = apiUrl(`/api/models/${encodeURIComponent(connectionId)}`);
        const resp = await fetchWithAuth(url.toString(), { method, headers: buildHeaders(true), body: JSON.stringify(payload), redirect: "follow" });
        if (!resp.ok) throw new Error(`update failed: ${resp.status}`);
        return (await resp.json()) as BackendModelItem;
    },

    async remove(connectionId: number | string): Promise<void> {
        const url = apiUrl(`/api/models/${encodeURIComponent(String(connectionId))}`);
        const resp = await fetchWithAuth(url.toString(), { method: "DELETE", headers: buildHeaders(false), redirect: "follow" });
        if (resp.status === 200 || resp.status === 204) return;
        let payload: unknown = undefined;
        try { const ct = resp.headers.get("content-type") || ""; payload = ct.includes("application/json") ? await resp.json() : await resp.text(); } catch { }
        if (resp.status === 404) throw new NotFoundError("记录不存在", payload);
        if (resp.status === 422) throw new ValidationError("参数错误", payload);
        throw new HttpError(`delete failed: ${resp.status}`, resp.status, payload);
    },
};
