import { NextResponse } from 'next/server';
import { listModels, postModel } from '@/lib/server/monitorApi';

export async function GET() {
  return NextResponse.json(listModels());
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  return NextResponse.json(postModel(body), { status: 201 });
}
