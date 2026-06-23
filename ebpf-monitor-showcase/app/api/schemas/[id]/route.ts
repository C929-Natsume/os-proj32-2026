import { NextResponse } from 'next/server';
import { getSchema, putSchema, removeSchema } from '@/lib/server/monitorApi';

export async function GET(_: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const item = getSchema(Number(id));
  return item ? NextResponse.json(item) : NextResponse.json({ error: 'not found' }, { status: 404 });
}

export async function PUT(req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const body = await req.json().catch(() => ({}));
  const item = putSchema(Number(id), body);
  return item ? NextResponse.json(item) : NextResponse.json({ error: 'not found' }, { status: 404 });
}

export async function PATCH(req: Request, context: { params: Promise<{ id: string }> }) {
  return PUT(req, context);
}

export async function DELETE(_: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return removeSchema(Number(id)) ? NextResponse.json({ ok: true }) : NextResponse.json({ error: 'not found' }, { status: 404 });
}
