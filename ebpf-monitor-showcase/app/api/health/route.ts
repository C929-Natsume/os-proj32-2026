import { NextResponse } from 'next/server';
import { getHealth } from '@/lib/server/monitorApi';

export async function GET() {
  return NextResponse.json(getHealth());
}
