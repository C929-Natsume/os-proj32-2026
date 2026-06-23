import { NextResponse } from 'next/server';
import { getOverview } from '@/lib/server/monitorApi';

export async function GET() {
  return NextResponse.json(getOverview());
}
