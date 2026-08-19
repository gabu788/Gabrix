export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const code = String(body.accessCode || "").trim();

    if (!/^\d{4}$/.test(code)) {
      return Response.json(
        { error: "Enter a valid 4-digit admin code." },
        { status: 400 }
      );
    }

    if (!context.env.ADMIN_SECRET) {
      return Response.json(
        { error: "Admin authentication is not configured." },
        { status: 500 }
      );
    }

    if (code !== String(context.env.ADMIN_SECRET).trim()) {
      return Response.json(
        { error: "Access denied. Invalid admin code." },
        { status: 401 }
      );
    }

    const token = crypto.randomUUID();

    return Response.json(
      { ok: true, token },
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
