import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * lacesOS AI gateway
 *
 * Deploy this directory as the Supabase Edge Function named "ai-gateway".
 * If this gateway uses its own device-token authentication, deploy with JWT
 * verification disabled at the Supabase gateway; this function performs its
 * own per-device authorization checks.
 */

const corsHeaders = {
  // The OS may be opened from a local file, which browsers report as origin "null".
  // This endpoint does not use cookie-based authentication.
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, apikey, x-client-info, content-type, x-ai-device-token",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const geminiApiKey = Deno.env.get("GEMINI_API_KEY") ?? "";
const geminiModel = Deno.env.get("GEMINI_MODEL") ?? "gemini-3.5-flash-lite";

const db = supabaseUrl && serviceRoleKey
  ? createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    })
  : null;

function reply(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

function cleanString(value: unknown, max: number): string {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function isDeviceId(value: string): boolean {
  return /^dev_[A-Za-z0-9_-]{8,150}$/.test(value);
}

Deno.serve(async (req: Request) => {
  // Always handle preflight before checking method, body, or secrets.
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return reply(405, { error: "Use POST." });
  }

  if (!supabaseUrl || !serviceRoleKey || !db) {
    return reply(500, {
      error: "Supabase server configuration is missing. Check the Edge Function environment.",
    });
  }

  let body: Record<string, unknown>;
  try {
    const parsed = await req.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return reply(400, { error: "Request body must be a JSON object." });
    }
    body = parsed as Record<string, unknown>;
  } catch {
    return reply(400, { error: "Request body must be JSON." });
  }

  const action = cleanString(body.action, 20);
  const deviceId = cleanString(body.device_id, 160);
  const username = cleanString(body.username, 80);

  if (!isDeviceId(deviceId)) {
    return reply(400, {
      error: "Open this app from your lacesOS hub; a valid device ID was not found.",
    });
  }

  if (action === "status") {
    // A browser-supplied device ID by itself never grants AI access.
    const { data: registeredDevice, error: deviceError } = await db
      .from("devices")
      .select("device_id")
      .eq("device_id", deviceId)
      .maybeSingle();

    if (deviceError) {
      return reply(500, { error: "Could not verify this lacesOS device." });
    }
    if (!registeredDevice) {
      return reply(200, { allowed: false });
    }

    const { data, error } = await db
      .from("ai_device_access")
      .select("enabled,blocked_at")
      .eq("device_id", deviceId)
      .maybeSingle();

    if (error) return reply(500, { error: "Could not check AI access." });

    return reply(200, {
      allowed: !!data && data.enabled === true && !data.blocked_at,
    });
  }

  if (action === "redeem") {
    const code = cleanString(body.code, 100).toUpperCase();
    if (!code || code.length < 10) {
      return reply(400, { error: "Enter the activation code you received." });
    }

    const token = randomToken();
    const [codeHash, tokenHash] = await Promise.all([
      sha256Hex(code),
      sha256Hex(token),
    ]);

    const { data, error } = await db.rpc("redeem_ai_code", {
      p_code_hash: codeHash,
      p_device_id: deviceId,
      p_username: username,
      p_token_hash: tokenHash,
    });

    if (error) {
      return reply(500, {
        error: "Activation failed because the server could not verify the code.",
      });
    }

    if (!data?.ok) {
      const message = data?.reason === "not_approved"
        ? "This device is not approved for AI access. Ask the hub owner."
        : "That code is invalid, expired, revoked, already used, or assigned to a different device.";
      return reply(403, { error: message });
    }

    return reply(200, { ok: true, token, daily_limit: data.daily_limit });
  }

  if (action === "chat") {
    if (!geminiApiKey) {
      return reply(503, {
        error: "AI service is not configured yet. The hub owner must add GEMINI_API_KEY to Edge Function secrets.",
      });
    }

    const token = cleanString(req.headers.get("x-ai-device-token"), 200);
    if (token.length < 40) {
      return reply(401, {
        error: "Your activation session is missing. Re-enter your activation code.",
      });
    }

    const tokenHash = await sha256Hex(token);
    const { data: usage, error: usageError } = await db.rpc("consume_ai_request", {
      p_device_id: deviceId,
      p_token_hash: tokenHash,
    });

    if (usageError) {
      return reply(500, { error: "Could not verify AI access or update usage." });
    }

    if (!usage?.ok) {
      if (usage?.reason === "daily_limit") {
        return reply(429, {
          error: `Daily limit reached (${usage.daily_limit ?? 0} requests). Try again after the UTC daily reset or ask the hub owner to adjust your limit.`,
        });
      }
      if (usage?.reason === "minute_limit") {
        return reply(429, {
          error: "You are sending messages too quickly. The limit is 10 requests per minute; wait a moment and try again.",
        });
      }
      if (usage?.reason === "not_approved") {
        return reply(403, { error: "AI access has been disabled for this device." });
      }
      return reply(401, {
        error: "Your activation session is invalid or revoked. Ask the hub owner for a new code.",
      });
    }

    const rawContents = Array.isArray(body.contents) ? body.contents.slice(-24) : [];
    const contents = rawContents.map((entry) => {
      if (!entry || typeof entry !== "object") return { role: "", parts: [] };
      const item = entry as Record<string, unknown>;
      const role = item.role === "model" ? "model" : item.role === "user" ? "user" : "";
      const parts = Array.isArray(item.parts)
        ? item.parts.slice(0, 8)
            .map((part) => ({
              text: part && typeof part === "object"
                ? cleanString((part as Record<string, unknown>).text, 12000)
                : "",
            }))
            .filter((part) => part.text)
        : [];
      return { role, parts };
    }).filter((entry) => entry.role && entry.parts.length > 0);

    if (!contents.length || contents[contents.length - 1].role !== "user") {
      return reply(400, { error: "Send a message before requesting a response." });
    }

    const totalChars = contents.reduce(
      (sum, item) => sum + item.parts.reduce((partSum, part) => partSum + part.text.length, 0),
      0,
    );
    if (totalChars > 40000) {
      return reply(413, {
        error: "This conversation is too long. Start a new chat or remove some history.",
      });
    }

    let upstream: Response;
    try {
      upstream = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(geminiModel)}:generateContent`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": geminiApiKey,
          },
          body: JSON.stringify({
            contents,
            generationConfig: { temperature: 0.7, maxOutputTokens: 2048 },
          }),
        },
      );
    } catch {
      return reply(502, {
        error: "Could not connect to Gemini. Your request may still count toward the daily limit.",
      });
    }

    const upstreamData = await upstream.json().catch(() => ({}));
    if (!upstream.ok) {
      const detail = cleanString(upstreamData?.error?.message, 500);
      if (upstream.status === 429) {
        return reply(429, {
          error: "Gemini's own project quota or rate limit was reached. This is separate from your per-device limit.",
        });
      }
      return reply(502, { error: `Gemini returned an error (${upstream.status}). ${detail}` });
    }

    const answer = Array.isArray(upstreamData?.candidates?.[0]?.content?.parts)
      ? upstreamData.candidates[0].content.parts
          .map((part: { text?: string }) => part.text || "")
          .join("")
          .trim()
      : "";

    if (!answer) {
      return reply(502, { error: "Gemini returned no text. Try rephrasing the message." });
    }

    return reply(200, {
      answer,
      usage: { used: usage.used, daily_limit: usage.daily_limit },
    });
  }

  return reply(400, { error: "Unknown action." });
});
