export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const code = String(body.code || "").trim();

    if (!code) {
      return Response.json(
        { error: "Enter your campaign code." },
        { status: 400 }
      );
    }

    const buffer = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(code)
    );

    const hash = [...new Uint8Array(buffer)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    const client = await context.env.DB
      .prepare(`
        SELECT name, campaign, package, status, progress, update_note
        FROM clients
        WHERE code_hash = ? AND active = 1
      `)
      .bind(hash)
      .first();

    if (!client) {
      return Response.json(
        { error: "Invalid campaign code. Please contact GABRIX." },
        { status: 401 }
      );
    }

    return Response.json({ client });

  } catch (error) {
    return Response.json(
      { error: "Unable to access the campaign desk right now." },
      { status: 500 }
    );
  }
}
