export async function onRequestPost(context) {
  const suppliedSecret = context.request.headers.get("x-gabrix-admin-secret");

  if (!suppliedSecret || suppliedSecret !== context.env.ADMIN_SECRET) {
    return Response.json(
      { error: "Unauthorized" },
      { status: 401 }
    );
  }

  try {
    const data = await context.request.json();

    const required = [
      "name",
      "campaign",
      "package",
      "status",
      "progress",
      "update_note",
      "code"
    ];

    for (const field of required) {
      if (!String(data[field] ?? "").trim()) {
        return Response.json(
          { error: `Missing ${field}` },
          { status: 400 }
        );
      }
    }

    const buffer = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(String(data.code).trim())
    );

    const hash = [...new Uint8Array(buffer)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    await context.env.DB.prepare(`
      INSERT INTO clients
      (name, campaign, package, status, progress, update_note, code_hash, active)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
      ON CONFLICT(code_hash) DO UPDATE SET
        name=excluded.name,
        campaign=excluded.campaign,
        package=excluded.package,
        status=excluded.status,
        progress=excluded.progress,
        update_note=excluded.update_note,
        active=1
    `).bind(
      data.name,
      data.campaign,
      data.package,
      data.status,
      data.progress,
      data.update_note,
      hash
    ).run();

    return Response.json({ ok: true });

  } catch (error) {
    return Response.json(
      { error: "Unable to save client." },
      { status: 500 }
    );
  }
}
