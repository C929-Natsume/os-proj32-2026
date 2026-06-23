import { buildHeaders } from "@/lib/serviceUtils";
import { fetchWithAuth } from "@/lib/auth";
import { HttpError, NotFoundError, ValidationError } from "@/lib/errors";

const BASE_URL = process.env.NEXT_PUBLIC_SQLOPT_SERVICE_URL || "";

function apiUrl(path: string) {
    const origin = typeof window !== "undefined" ? window.location.origin : "http://localhost";
    return new URL(path, BASE_URL || origin);
}

export type CreateDbSchema = Record<string, unknown>;
export type UpdateDbSchema = Record<string, unknown>;

export interface BackendDbSchemaItem {
    id: number;
    schema_name: string;
    schema_content: string;
    created_at: string;
    updated_at: string;
    user_id: number;
    [key: string]: unknown;
}

export interface ListDbSchemasResponse {
    schemas: BackendDbSchemaItem[];
    total: number;
    skip: number;
    limit: number;
    has_more?: boolean;
    active_schema_id?: number;
}

export const schemaApi = {
    async getActive(): Promise<BackendDbSchemaItem> {
        const url = apiUrl("/api/schemas/active");
        const resp = await fetchWithAuth(url.toString(), { method: "GET", headers: buildHeaders(false), redirect: "follow" });
        if (resp.ok) return (await resp.json()) as BackendDbSchemaItem;
        let payload: unknown = undefined;
        try { const ct = resp.headers.get("content-type") || ""; payload = ct.includes("application/json") ? await resp.json() : await resp.text(); } catch { }
        if (resp.status === 404) throw new NotFoundError("未找到活跃数据库模式", payload);
        if (resp.status === 422) throw new ValidationError("参数错误", payload);
        throw new HttpError(`schema getActive failed: ${resp.status}`, resp.status, payload);
    },
    async list(params?: { skip?: number; limit?: number }): Promise<ListDbSchemasResponse> {
        const url = apiUrl("/api/schemas/");
        const skip = params?.skip ?? 0;
        const limit = params?.limit ?? 100;
        url.searchParams.set("skip", String(skip));
        url.searchParams.set("limit", String(limit));
        const resp = await fetchWithAuth(url.toString(), { method: "GET", headers: buildHeaders(false), redirect: "follow" });
        if (!resp.ok) throw new Error(`schema list failed: ${resp.status}`);
        const data = await resp.json().catch(() => undefined);
        if (!data || !Array.isArray(data.schemas)) return { schemas: [], total: 0, skip, limit };
        return data as ListDbSchemasResponse;
    },
    async create(payload: CreateDbSchema): Promise<BackendDbSchemaItem> {
        const url = apiUrl("/api/schemas/");
        const resp = await fetchWithAuth(url.toString(), { method: "POST", headers: buildHeaders(true), body: JSON.stringify(payload), redirect: "follow" });
        if (!resp.ok) throw new Error(`schema create failed: ${resp.status}`);
        return (await resp.json()) as BackendDbSchemaItem;
    },
    async setActive(schemaId: number | string) {
        const url = apiUrl("/api/schemas/active");
        const resp = await fetchWithAuth(url.toString(), { method: "POST", headers: buildHeaders(true), body: JSON.stringify({ schema_id: Number(schemaId) }), redirect: "follow" });
        if (resp.ok) { try { return await resp.json(); } catch { return { message: "OK" }; } }
        let payload: unknown = undefined;
        try { const ct = resp.headers.get("content-type") || ""; payload = ct.includes("application/json") ? await resp.json() : await resp.text(); } catch { }
        if (resp.status === 404) throw new NotFoundError("记录不存在", payload);
        if (resp.status === 422) throw new ValidationError("参数错误", payload);
        throw new HttpError(`schema setActive failed: ${resp.status}`, resp.status, payload);
    },
    async get(schemaId: number | string): Promise<BackendDbSchemaItem> {
        const url = apiUrl(`/api/schemas/${encodeURIComponent(String(schemaId))}`);
        const resp = await fetchWithAuth(url.toString(), { method: "GET", headers: buildHeaders(false), redirect: "follow" });
        if (resp.ok) return (await resp.json()) as BackendDbSchemaItem;
        let payload: unknown = undefined;
        try { const ct = resp.headers.get("content-type") || ""; payload = ct.includes("application/json") ? await resp.json() : await resp.text(); } catch { }
        if (resp.status === 404) throw new NotFoundError("数据库模式不存在", payload);
        if (resp.status === 422) throw new ValidationError("参数错误", payload);
        throw new HttpError(`schema get failed: ${resp.status}`, resp.status, payload);
    },
    async update(schemaId: number | string, payload: UpdateDbSchema, method: "PUT" | "PATCH" = "PUT"): Promise<BackendDbSchemaItem> {
        const url = apiUrl(`/api/schemas/${encodeURIComponent(String(schemaId))}`);
        const resp = await fetchWithAuth(url.toString(), { method, headers: buildHeaders(true), body: JSON.stringify(payload), redirect: "follow" });
        if (!resp.ok) throw new Error(`schema update failed: ${resp.status}`);
        return (await resp.json()) as BackendDbSchemaItem;
    },
    async remove(schemaId: number | string): Promise<void> {
        const url = apiUrl(`/api/schemas/${encodeURIComponent(String(schemaId))}`);
        const resp = await fetchWithAuth(url.toString(), { method: "DELETE", headers: buildHeaders(false), redirect: "follow" });
        if (resp.status === 200 || resp.status === 204) return;
        let payload: unknown = undefined;
        try { const ct = resp.headers.get("content-type") || ""; payload = ct.includes("application/json") ? await resp.json() : await resp.text(); } catch { }
        if (resp.status === 404) throw new NotFoundError("数据库模式不存在", payload);
        if (resp.status === 422) throw new ValidationError("参数错误", payload);
        throw new HttpError(`schema delete failed: ${resp.status}`, resp.status, payload);
    },
};
