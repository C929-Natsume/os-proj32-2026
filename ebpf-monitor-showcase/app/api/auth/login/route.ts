import { NextResponse } from 'next/server';
import { handleAuthLogin } from '@/lib/server/monitorApi';

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  return NextResponse.json(handleAuthLogin(body));
}
