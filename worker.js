const ALLOWED_ORIGIN = "https://gabrixnetwork.pages.dev";

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin":
      origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400"
  };
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(origin)
    }
  });
}

function randomId() {
  return crypto.randomUUID();
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  return Array.from(
    bytes,
    b => b.toString(16).padStart(2, "0")
  ).join("");
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return Array.from(
    new Uint8Array(digest),
    b => b.toString(16).padStart(2, "0")
  ).join("");
}

function getBearerToken(request) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) {
    return "";
  }

  return header.slice(7).trim();
}

async function requireAdmin(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    return null;
  }

  const tokenHash = await sha256(token);

  const row = await env.DB.prepare(`
    SELECT
      s.id,
      s.user_id,
      s.expires_at,
      s.revoked_at,
      u.account_type,
      u.status
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (!row) {
    return null;
  }

  if (row.revoked_at) {
    return null;
  }

  if (new Date(row.expires_at).getTime() <= Date.now()) {
    return null;
  }

  if (row.account_type !== "admin") {
    return null;
  }

  if (row.status !== "active") {
    return null;
  }

  return row;
}

async function adminLogin(request, env) {
  if (!env.ADMIN_CODE) {
    return json(
      {
        error:
          "Admin authentication is not configured on the GABRIX server."
      },
      503
    );
  }

  let body = {};

  try {
    body = await request.json();
  } catch {}

  const suppliedPin = String(
    body.pin ?? body.accessCode ?? ""
  ).trim();

  const configuredPin = String(env.ADMIN_CODE).trim();

  if (!/^\d{4}$/.test(suppliedPin)) {
    return json(
      {
        error: "Access denied. Please check the admin PIN."
      },
      401
    );
  }

  if (suppliedPin !== configuredPin) {
    return json(
      {
        error: "Access denied. Please check the admin PIN."
      },
      401
    );
  }

  let admin = await env.DB.prepare(`
    SELECT
      id,
      full_name,
      email,
      phone,
      account_type,
      status
    FROM users
    WHERE account_type = 'admin'
    ORDER BY created_at ASC
    LIMIT 1
  `).first();

  if (!admin) {
    const now = new Date().toISOString();
    const id = randomId();
    const email = "admin@gabrixnetwork.local";
    const temporaryPasswordHash = await sha256(randomToken());

    await env.DB.prepare(`
      INSERT INTO users
      (
        id,
        full_name,
        email,
        phone,
        account_type,
        password_hash,
        status,
        email_verified_at,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      "GABRIX Administrator",
      email,
      "",
      "admin",
      temporaryPasswordHash,
      "active",
      now,
      now,
      now
    ).run();

    admin = {
      id,
      full_name: "GABRIX Administrator",
      email,
      phone: "",
      account_type: "admin",
      status: "active"
    };
  }

  const token = randomToken();
  const tokenHash = await sha256(token);
  const sessionId = randomId();

  const createdAt = new Date();
  const expiresAt = new Date(
    createdAt.getTime() + 8 * 60 * 60 * 1000
  ).toISOString();

  await env.DB.prepare(`
    INSERT INTO sessions
    (
      id,
      user_id,
      token_hash,
      expires_at,
      revoked_at,
      created_at
    )
    VALUES (?, ?, ?, ?, NULL, ?)
  `).bind(
    sessionId,
    admin.id,
    tokenHash,
    expiresAt,
    createdAt.toISOString()
  ).run();

  return json({
    ok: true,
    token,
    expiresAt,
    user: {
      id: admin.id,
      name: admin.full_name,
      email: admin.email,
      accountType: admin.account_type
    }
  });
}

async function listClients(request, env) {
  const admin = await requireAdmin(request, env);

  if (!admin) {
    return json(
      {
        error: "Unauthorized."
      },
      401
    );
  }

  const result = await env.DB.prepare(`
    SELECT
      id,
      name,
      project,
      package,
      campaign,
      code,
      target_subs,
      target_likes,
      target_comments,
      target_watch,
      status,
      progress,
      update_note,
      created_at,
      updated_at
    FROM clients
    ORDER BY created_at DESC
  `).all();

  return json({
    ok: true,
    clients: result.results || []
  });
}

async function createClient(request, env) {
  const admin = await requireAdmin(request, env);

  if (!admin) {
    return json(
      {
        error: "Unauthorized."
      },
      401
    );
  }

  let body = {};

  try {
    body = await request.json();
  } catch {
    return json(
      {
        error: "Invalid JSON."
      },
      400
    );
  }

  const name = String(body.name || "").trim();
  const project = String(body.project || "").trim();
  const packageName = String(body.package || "").trim();
  const campaign = String(body.campaign || "").trim();
  const code = String(body.code || "").trim();

  if (!name || !project || !packageName || !code) {
    return json(
      {
        error:
          "Name, project, package and client code are required."
      },
      400
    );
  }

  if (!/^\d{4}$/.test(code)) {
    return json(
      {
        error:
          "Client code must contain exactly 4 digits."
      },
      400
    );
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM clients
    WHERE code = ?
    LIMIT 1
  `).bind(code).first();

  if (existing) {
    return json(
      {
        error:
          "That client code is already in use."
      },
      409
    );
  }

  const now = new Date().toISOString();
  const id = randomId();

  await env.DB.prepare(`
    INSERT INTO clients
    (
      id,
      name,
      project,
      package,
      campaign,
      code,
      target_subs,
      target_likes,
      target_comments,
      target_watch,
      status,
      progress,
      update_note,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, '', ?, ?)
  `).bind(
    id,
    name,
    project,
    packageName,
    campaign,
    code,
    Number(body.target_subs || 0),
    Number(body.target_likes || 0),
    Number(body.target_comments || 0),
    Number(body.target_watch || 0),
    now,
    now
  ).run();

  const client = await env.DB.prepare(`
    SELECT *
    FROM clients
    WHERE id = ?
  `).bind(id).first();

  return json({
    ok: true,
    client
  });
}

async function clientLogin(request, env) {
  let body = {};

  try {
    body = await request.json();
  } catch {}

  const code = String(
    body.code ??
    body.clientCode ??
    body.accessCode ??
    ""
  ).trim();

  if (!code) {
    return json(
      {
        error: "Client code is required."
      },
      400
    );
  }

  const client = await env.DB.prepare(`
    SELECT *
    FROM clients
    WHERE code = ?
    LIMIT 1
  `).bind(code).first();

  if (!client) {
    return json(
      {
        error: "Invalid client code."
      },
      401
    );
  }

  if (
    client.status &&
    String(client.status).toUpperCase() !== "ACTIVE"
  ) {
    return json(
      {
        error: "This client account is not active."
      },
      403
    );
  }

  return json({
    ok: true,
    client
  });
}

async function logout(request, env) {
  const token = getBearerToken(request);

  if (token) {
    const tokenHash = await sha256(token);

    await env.DB.prepare(`
      UPDATE sessions
      SET revoked_at = ?
      WHERE token_hash = ?
    `).bind(
      new Date().toISOString(),
      tokenHash
    ).run();
  }

  return json({
    ok: true
  });
}

export default {
  async fetch(request, env) {
    const origin =
      request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin)
      });
    }

    const url = new URL(request.url);

    const path =
      url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (
        request.method === "POST" &&
        (
          path === "/api/admin/login" ||
          path === "/api/admin-login"
        )
      ) {
        return await adminLogin(request, env);
      }

      if (
        request.method === "POST" &&
        (
          path === "/api/client/login" ||
          path === "/api/client-login"
        )
      ) {
        return await clientLogin(request, env);
      }

      if (
        request.method === "POST" &&
        path === "/api/admin/logout"
      ) {
        return await logout(request, env);
      }

      if (
        request.method === "GET" &&
        (
          path === "/api/admin/clients" ||
          path === "/api/clients"
        )
      ) {
        return await listClients(request, env);
      }

      if (
        request.method === "POST" &&
        (
          path === "/api/admin/clients" ||
          path === "/api/clients"
        )
      ) {
        return await createClient(request, env);
      }

      if (
        path === "/" ||
        path === "/health"
      ) {
        return json({
          ok: true,
          service: "GABRIX NETWORK API",
          status: "online"
        });
      }

      return json(
        {
          error: "Route not found."
        },
        404
      );
    } catch (error) {
      console.error(error);

      return json(
        {
          error: "GABRIX server error.",
          detail:
            error?.message ||
            "Unknown error."
        },
        500
      );
    }
  }
};
 
