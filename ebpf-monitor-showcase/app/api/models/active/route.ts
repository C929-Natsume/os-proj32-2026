import { NextResponse } from 'next/server';
import { activateModel, listModels } from '@/lib/server/monitorApi';

export async function GET() {
  const data = listModels();
  const active = data.models.find((m) => Number(m.id) === Number(data.active_connection_id)) || data.models[0] || null;
  return active ? NextResponse.json(active) : NextResponse.json({ error: 'not found' }, { status: 404 });
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const ok = activateModel(Number(body?.connection_id));
  return ok ? NextResponse.json({ message: 'OK' }) : NextResponse.json({ error: 'not found' }, { status: 404 });
}
