import { NextResponse } from 'next/server';
import { getAnomalies } from '@/lib/server/monitorApi';

export async function GET(req: Request) {
  const url = new URL(req.url);
  const limit = Number(url.searchParams.get('limit') || '50');
  return NextResponse.json({ anomalies: getAnomalies(Number.isFinite(limit) ? limit : 50) });
}
