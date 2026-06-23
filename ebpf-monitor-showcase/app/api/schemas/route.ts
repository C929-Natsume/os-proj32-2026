import { NextResponse } from 'next/server';
import { listSchemas, postSchema } from '@/lib/server/monitorApi';

export async function GET() {
  return NextResponse.json(listSchemas());
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  return NextResponse.json(postSchema(body), { status: 201 });
}
