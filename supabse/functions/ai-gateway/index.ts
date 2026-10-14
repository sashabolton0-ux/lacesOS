import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// LacesOS AI gateway. AI credentials and all access checks stay server-side.
// Deploy as the Supabase Edge Function named `ai-gateway`.
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const geminiApiKey = Deno.env.get("GEMINI_API_KEY") ?? "";
const geminiModel = Deno.env.get("GEMINI_MODEL") ?? "gemini-3.5-flash-lite";
const db = supabaseUrl && serviceRoleKey
  ? createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false, autoRefreshToken: false } })
  : null;

function reply(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });
}
function cleanString(value: unknown, max: number): string {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function isDeviceId(value: string): boolean {
  return /^dev_[A-Za-z0-9_-]{8,150}$/.test(value);
}

async function verifyRegisteredDevice(deviceId: string) {
  if (!db) throw new Error("Supabase server configuration is missing.");
  const { data, error } = await db.from("devices").select("device_id").eq("device_id", deviceId).maybeSingle();
  if (error) throw new Error("Could not verify this LacesOS device.");
  return !!data;
}

Deno.serve(async (req: Request) => {
  // Local-file/about:blank clients send Origin: null; CORS must still answer preflight.
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  if (req.method !== "POST") return reply(405, { error: "Use POST." });
  if (!db) return reply(500, { error: "Supabase server configuration is missing. Check the Edge Function environment." });

  let body: Record<string, unknown>;
  try {
    const parsed = await req.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return reply(400, { error: "Request body must be a JSON object." });
    body = parsed as Record<string, unknown>;
  } catch {
    return reply(400, { error: "Request body must be JSON." });
  }

  const action = cleanString(body.action, 32);
  const deviceId = cleanString(body.device_id, 160);
  const username = cleanString(body.username, 80);
  if (!isDeviceId(deviceId)) return reply(400, { error: "Open this app from your LacesOS hub; a valid device ID was not found." });

  if (action === "save_private_name") {
    const realName = cleanString(body.real_name, 100);
    if (realName.length > 100) return reply(400, { error: "Please use a shorter name." });
    try {
      if (!await verifyRegisteredDevice(deviceId)) return reply(403, { error: "This device is not registered yet. Reload LacesOS and try again." });
      const { error } = await db.from("device_private_profiles").upsert({
        device_id: deviceId,
        real_name: realName || null,
        updated_at: new Date().toISOString(),
      }, { onConflict: "device_id" });
      if (error) return reply(500, { error: "Could not save the private name. You can continue without it." });
      return reply(200, { ok: true });
    } catch (error) {
      return reply(500, { error: error instanceof Error ? error.message : "Could not save the private name." });
    }
  }

  if (action === "status") {
    try {
      if (!await verifyRegisteredDevice(deviceId)) return reply(200, { allowed: false, reason: "device_not_registered" });
      const { data: access, error } = await db.from("ai_device_access")
        .select("enabled,blocked_at,daily_limit").eq("device_id", deviceId).maybeSingle();
      if (error) return reply(500, { error: "Could not check AI access. Verify the AI access table migration was applied." });
      const allowed = !!access && access.enabled === true && !access.blocked_at;
      let used = 0;
      if (allowed) {
        const today = new Date().toISOString().slice(0, 10);
        const { data: usage } = await db.from("ai_request_counts_daily")
          .select("request_count").eq("device_id", deviceId).eq("usage_date", today).maybeSingle();
        used = Number(usage?.request_count || 0);
      }
      return reply(200, { allowed, daily_limit: Number(access?.daily_limit ?? 20), used });
    } catch (error) {
      return reply(500, { error: error instanceof Error ? error.message : "Could not verify AI access." });
    }
  }

  if (action === "chat") {
    if (!geminiApiKey) return reply(503, { error: "AI is not configured yet. Add GEMINI_API_KEY to the ai-gateway Edge Function secrets." });
    try {
      if (!await verifyRegisteredDevice(deviceId)) return reply(403, { error: "This LacesOS device is not registered. Reopen the app from LacesOS." });
    } catch (error) {
      return reply(500, { error: error instanceof Error ? error.message : "Could not verify this device." });
    }

    const rawContents = Array.isArray(body.contents) ? body.contents.slice(-24) : [];
    const contents = rawContents.map((entry) => {
      if (!entry || typeof entry !== "object") return { role: "", parts: [] as { text: string }[] };
      const item = entry as Record<string, unknown>;
      const role = item.role === "model" ? "model" : item.role === "user" ? "user" : "";
      const parts = Array.isArray(item.parts) ? item.parts.slice(0, 8).map((part) => ({
        text: part && typeof part === "object" ? cleanString((part as Record<string, unknown>).text, 12000) : "",
      })).filter((part) => part.text) : [];
      return { role, parts };
    }).filter((entry) => entry.role && entry.parts.length > 0);

    if (!contents.length || contents[contents.length - 1].role !== "user") return reply(400, { error: "Send a message before requesting a response." });
    const totalChars = contents.reduce((sum, item) => sum + item.parts.reduce((partSum, part) => partSum + part.text.length, 0), 0);
    if (totalChars > 40000) return reply(413, { error: "This conversation is too long. Start a new chat or remove some history." });

    const { data: usage, error: usageError } = await db.rpc("consume_ai_request_v2", { p_device_id: deviceId });
    if (usageError) return reply(500, { error: "Could not enforce AI limits. Apply the LacesOS AI access SQL first." });
    if (!usage?.ok) {
      if (usage?.reason === "daily_limit") return reply(429, { error: `Daily limit reached (${usage.daily_limit ?? 0} requests). Try again after the UTC daily reset.` });
      if (usage?.reason === "minute_limit") return reply(429, { error: "You are sending messages too quickly. The limit is 10 requests per minute; wait a moment and try again." });
      if (usage?.reason === "not_approved") return reply(403, { error: "AI access is not enabled for this device. Ask the LacesOS owner to enable it." });
      return reply(403, { error: "AI access is not enabled for this device." });
    }

    let upstream: Response;
    try {
      upstream = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(geminiModel)}:generateContent`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-goog-api-key": geminiApiKey },
        body: JSON.stringify({ contents, generationConfig: { temperature: 0.7, maxOutputTokens: 2048 } }),
      });
    } catch {
      return reply(502, { error: "Could not connect to Gemini. Please try again shortly." });
    }

    const upstreamData = await upstream.json().catch(() => ({}));
    if (!upstream.ok) {
      const detail = cleanString(upstreamData?.error?.message, 400);
      if (upstream.status === 429) return reply(429, { error: "Gemini's own project quota or rate limit was reached. This is separate from your LacesOS limit." });
      return reply(502, { error: `Gemini returned an error (${upstream.status}). ${detail}` });
    }
    const answer = Array.isArray(upstreamData?.candidates?.[0]?.content?.parts)
      ? upstreamData.candidates[0].content.parts.map((part: { text?: string }) => part.text || "").join("").trim()
      : "";
    if (!answer) return reply(502, { error: "Gemini returned no text. Try rephrasing the message." });
    return reply(200, { answer, usage: { used: usage.used, daily_limit: usage.daily_limit } });
  }

  return reply(400, { error: "Unknown action." });
});
