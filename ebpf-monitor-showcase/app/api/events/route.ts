import { NextResponse } from 'next/server';
import { getEvents } from '@/lib/server/monitorApi';

export async function GET(req: Request) {
  const url = new URL(req.url);
  const limit = Number(url.searchParams.get('limit') || '50');
  return NextResponse.json({ events: getEvents(Number.isFinite(limit) ? limit : 50) });
}
