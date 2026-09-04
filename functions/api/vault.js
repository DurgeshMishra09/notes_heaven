const MAX_FILE_SIZE = 25 * 1024 * 1024;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function authorized(request, env) {
  const password = request.headers.get("X-Vault-Password");
  return password && password === env.VAULT_PASSWORD;
}

export async function onRequest(context) {
  const { request, env } = context;

  if (!authorized(request, env)) {
    return json({ error: "Wrong or missing password" }, 401);
  }

  const url = new URL(request.url);
  const action = url.searchParams.get("action");

  try {
    // LIST FILES
    if (request.method === "GET" && action === "list") {
      const result = await env.VAULT_KV.list({ prefix: "file:" });

      const files = result.keys.map(item => ({
        id: item.name.replace("file:", ""),
        name: item.metadata?.name || "Unnamed file",
        type: item.metadata?.type || "application/octet-stream",
        size: item.metadata?.size || 0
      }));

      return json({ files });
    }

    // UPLOAD FILE
    if (request.method === "POST" && action === "upload") {
      const name = url.searchParams.get("name") || "file";
      const safeName = name.replace(/[\/\\]/g, "_").slice(0, 200);

      const contentLength = Number(request.headers.get("Content-Length") || 0);

      if (contentLength > MAX_FILE_SIZE) {
        return json({ error: "File is larger than 25 MB" }, 413);
      }

      const data = await request.arrayBuffer();

      if (data.byteLength > MAX_FILE_SIZE) {
        return json({ error: "File is larger than 25 MB" }, 413);
      }

      const id = crypto.randomUUID();
      const key = "file:" + id;

      await env.VAULT_KV.put(key, data, {
        metadata: {
          name: safeName,
          type: request.headers.get("Content-Type") || "application/octet-stream",
          size: data.byteLength
        }
      });

      return json({
        success: true,
        id,
        name: safeName
      }, 201);
    }

    // DOWNLOAD FILE
    if (request.method === "GET" && action === "download") {
      const id = url.searchParams.get("id");

      if (!id) {
        return json({ error: "Missing file ID" }, 400);
      }

      const key = "file:" + id;

      const metadataResult = await env.VAULT_KV.list({
        prefix: key,
        limit: 1
      });

      if (!metadataResult.keys.length) {
        return json({ error: "File not found" }, 404);
      }

      const metadata = metadataResult.keys[0].metadata || {};
      const data = await env.VAULT_KV.get(key, "arrayBuffer");

      if (data === null) {
        return json({ error: "File not found" }, 404);
      }

      const filename = metadata.name || "download";
      const type = metadata.type || "application/octet-stream";

      return new Response(data, {
        status: 200,
        headers: {
          "Content-Type": type,
          "Content-Disposition":
            `attachment; filename="download"; filename*=UTF-8''${encodeURIComponent(filename)}`
        }
      });
    }

    // DELETE FILE
    if (request.method === "DELETE" && action === "delete") {
      const id = url.searchParams.get("id");

      if (!id) {
        return json({ error: "Missing file ID" }, 400);
      }

      await env.VAULT_KV.delete("file:" + id);

      return json({ success: true });
    }

    return json({ error: "Invalid request" }, 400);

  } catch (error) {
    return json({
      error: "Server error",
      message: error.message
    }, 500);
  }
}
