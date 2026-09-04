const MAX_FILE_SIZE = 25 * 1024 * 1024;
const TOKEN_TTL_SECONDS = 120;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function authorized(request, env) {
  const password = request.headers.get("X-Vault-Password");
  return (
    typeof password === "string" &&
    password.length > 0 &&
    password === env.VAULT_PASSWORD
  );
}

function base64urlEncode(bytes) {
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + chunkSize)
    );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64urlDecode(value) {
  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "===".slice((value.length + 3) % 4);

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function signToken(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );

  return base64urlEncode(new Uint8Array(signature));
}

async function createToken(id, secret) {
  const payload = base64urlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        id: id,
        exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS
      })
    )
  );

  const signature = await signToken(payload, secret);

  return payload + "." + signature;
}

async function verifyToken(token, id, secret) {
  try {
    const parts = token.split(".");

    if (parts.length !== 2) {
      return false;
    }

    const payloadText = new TextDecoder().decode(
      base64urlDecode(parts[0])
    );

    const payload = JSON.parse(payloadText);

    if (
      payload.id !== id ||
      !Number.isFinite(payload.exp) ||
      payload.exp < Math.floor(Date.now() / 1000)
    ) {
      return false;
    }

    const expected = await signToken(
      parts[0],
      secret
    );

    if (expected.length !== parts[1].length) {
      return false;
    }

    let mismatch = 0;

    for (let i = 0; i < expected.length; i++) {
      mismatch |=
        expected.charCodeAt(i) ^
        parts[1].charCodeAt(i);
    }

    return mismatch === 0;

  } catch {
    return false;
  }
}

async function fileExists(env, id) {
  const result = await env.VAULT_KV.list({
    prefix: "file:" + id,
    limit: 1
  });

  return result.keys.length > 0;
}

export async function onRequest(context) {
  const { request, env } = context;

  const url = new URL(request.url);
  const action = url.searchParams.get("action");

  try {

    /*
     * Check that the required Cloudflare
     * bindings/secrets exist.
     */
    if (!env.VAULT_KV || !env.VAULT_PASSWORD) {
      return json(
        {
          error: "Vault is not configured"
        },
        500
      );
    }

    /*
     * DOWNLOAD TOKEN
     *
     * The frontend first asks for a short-lived
     * token. The password is required here.
     */
    if (action === "download-token") {

      if (
        request.method !== "POST" ||
        !authorized(request, env)
      ) {
        return json(
          {
            error: "Wrong or missing password"
          },
          401
        );
      }

      const id = url.searchParams.get("id");

      if (!id) {
        return json(
          {
            error: "Missing file ID"
          },
          400
        );
      }

      if (!(await fileExists(env, id))) {
        return json(
          {
            error: "File not found"
          },
          404
        );
      }

      const token = await createToken(
        id,
        env.VAULT_PASSWORD
      );

      return json({
        token: token
      });
    }

    /*
     * ACTUAL DOWNLOAD
     *
     * The browser can navigate directly to this URL.
     * This works better on both PC and mobile browsers.
     */
    if (
      action === "download" &&
      request.method === "GET"
    ) {

      const id = url.searchParams.get("id");
      const token = url.searchParams.get("token");

      if (!id) {
        return json(
          {
            error: "Missing file ID"
          },
          400
        );
      }

      const validToken = token
        ? await verifyToken(
            token,
            id,
            env.VAULT_PASSWORD
          )
        : false;

      /*
       * A valid short-lived token is accepted.
       * Direct password authentication is also
       * accepted for compatibility.
       */
      if (
        !validToken &&
        !authorized(request, env)
      ) {
        return json(
          {
            error: "Wrong or missing password"
          },
          401
        );
      }

      const key = "file:" + id;

      const listed = await env.VAULT_KV.list({
        prefix: key,
        limit: 1
      });

      if (!listed.keys.length) {
        return json(
          {
            error: "File not found"
          },
          404
        );
      }

      const metadata =
        listed.keys[0].metadata || {};

      const data =
        await env.VAULT_KV.get(
          key,
          {
            type: "arrayBuffer"
          }
        );

      if (data === null) {
        return json(
          {
            error: "File not found"
          },
          404
        );
      }

      const filename = String(
        metadata.name || "download"
      )
        .replace(/[\r\n"]/g, "_")
        .slice(0, 200);

      const type =
        metadata.type ||
        "application/octet-stream";

      return new Response(data, {
        status: 200,

        headers: {
          "Content-Type": type,

          "Content-Disposition":
            `attachment; filename="download"; filename*=UTF-8''${encodeURIComponent(filename)}`,

          "Content-Length":
            String(data.byteLength),

          "Cache-Control":
            "no-store"
        }
      });
    }

    /*
     * All other vault operations require
     * the vault password.
     */
    if (!authorized(request, env)) {
      return json(
        {
          error: "Wrong or missing password"
        },
        401
      );
    }

    /*
     * LIST FILES
     */
    if (
      request.method === "GET" &&
      action === "list"
    ) {

      const result =
        await env.VAULT_KV.list({
          prefix: "file:"
        });

      const files =
        result.keys.map(item => ({
          id: item.name.slice(5),

          name:
            item.metadata?.name ||
            "Unnamed file",

          type:
            item.metadata?.type ||
            "application/octet-stream",

          size:
            Number(
              item.metadata?.size || 0
            )
        }));

      return json({
        files: files
      });
    }

    /*
     * UPLOAD FILE
     */
    if (
      request.method === "POST" &&
      action === "upload"
    ) {

      const name =
        url.searchParams.get("name") ||
        "file";

      const safeName =
        name
          .replace(/[\/\\\r\n]/g, "_")
          .slice(0, 200);

      const data =
        await request.arrayBuffer();

      /*
       * Cloudflare KV maximum value size
       * is 25 MiB.
       */
      if (data.byteLength > MAX_FILE_SIZE) {
        return json(
          {
            error: "File is larger than 25 MB"
          },
          413
        );
      }

      const id =
        crypto.randomUUID();

      const key =
        "file:" + id;

      await env.VAULT_KV.put(
        key,
        data,
        {
          metadata: {
            name: safeName,

            type:
              request.headers.get(
                "Content-Type"
              ) ||
              "application/octet-stream",

            size:
              data.byteLength
          }
        }
      );

      return json(
        {
          success: true,
          id: id,
          name: safeName
        },
        201
      );
    }

    /*
     * DELETE FILE
     */
    if (
      request.method === "DELETE" &&
      action === "delete"
    ) {

      const id =
        url.searchParams.get("id");

      if (!id) {
        return json(
          {
            error: "Missing file ID"
          },
          400
        );
      }

      await env.VAULT_KV.delete(
        "file:" + id
      );

      return json({
        success: true
      });
    }

    /*
     * INVALID REQUEST
     */
    return json(
      {
        error: "Invalid request"
      },
      400
    );

  } catch (error) {

    return json(
      {
        error: "Server error",

        message:
          error instanceof Error
            ? error.message
            : String(error)
      },
      500
    );
  }
        }
