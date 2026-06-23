import { NextResponse } from 'next/server';
import { listDatabases, postDatabase } from '@/lib/server/monitorApi';

export async function GET() {
  return NextResponse.json(listDatabases());
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  return NextResponse.json(postDatabase(body), { status: 201 });
}
