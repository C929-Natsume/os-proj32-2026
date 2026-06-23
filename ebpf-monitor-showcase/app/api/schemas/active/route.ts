import { NextResponse } from 'next/server';
import { activateSchema, listSchemas } from '@/lib/server/monitorApi';

export async function GET() {
  const data = listSchemas();
  const active = data.schemas.find((m) => Number(m.id) === Number(data.active_schema_id)) || data.schemas[0] || null;
  return active ? NextResponse.json(active) : NextResponse.json({ error: 'not found' }, { status: 404 });
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const ok = activateSchema(Number(body?.schema_id));
  return ok ? NextResponse.json({ message: 'OK' }) : NextResponse.json({ error: 'not found' }, { status: 404 });
}
