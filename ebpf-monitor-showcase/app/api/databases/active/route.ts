import { NextResponse } from 'next/server';
import { activateDatabase, listDatabases } from '@/lib/server/monitorApi';

export async function GET() {
  const data = listDatabases();
  const active = data.databases.find((m) => Number(m.id) === Number(data.active_connection_id)) || data.databases[0] || null;
  return active ? NextResponse.json(active) : NextResponse.json({ error: 'not found' }, { status: 404 });
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const ok = activateDatabase(Number(body?.connection_id));
  return ok ? NextResponse.json({ message: 'OK' }) : NextResponse.json({ error: 'not found' }, { status: 404 });
}
