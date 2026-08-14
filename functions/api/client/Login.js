export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const code = String(body.code || "").trim();

    if (!/^\d{4}$/.test(code)) {
      return Response.json(
        { error: "Enter a valid 4-digit campaign code." },
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
        LIMIT 1
      `)
      .bind(hash)
      .first();

    if (!client) {
      return Response.json(
        { error: "Invalid campaign code. Please check your code." },
        { status: 401 }
      );
    }

    return Response.json(
      { client },
      {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          "Cache-Control": "no-store"
        }
      }
    );

  } catch (error) {
    return Response.json(
      { error: "Server error. Please try again." },
      {
        status: 500,
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          "Cache-Control": "no-store"
        }
      }
    );
  }
}
