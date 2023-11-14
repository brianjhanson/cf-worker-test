/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export interface Env {
	// Example binding to KV. Learn more at https://developers.cloudflare.com/workers/runtime-apis/kv/
	// MY_KV_NAMESPACE: KVNamespace;
	//
	// Example binding to Durable Object. Learn more at https://developers.cloudflare.com/workers/runtime-apis/durable-objects/
	// MY_DURABLE_OBJECT: DurableObjectNamespace;
	//
	// Example binding to R2. Learn more at https://developers.cloudflare.com/workers/runtime-apis/r2/
	// MY_BUCKET: R2Bucket;
	//
	// Example binding to a Service. Learn more at https://developers.cloudflare.com/workers/runtime-apis/service-bindings/
	// MY_SERVICE: Fetcher;
	//
	// Example binding to a Queue. Learn more at https://developers.cloudflare.com/queues/javascript-apis/
	// MY_QUEUE: Queue;
}

const SIGNATURE_PARAM = 's';
const KEY = "my secret symmetric key";

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    async function generateSignedUrl(url: URL) {
      // You will need some super-secret data to use as a symmetric key.
      const encoder = new TextEncoder();
      const secretKeyData = encoder.encode(KEY);
      const key = await crypto.subtle.importKey(
        "raw",
        secretKeyData,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );

      // Signed requests expire after one minute. Note that you could choose
      // expiration durations dynamically, depending on, for example, the path or a query
      // parameter.
      // const expirationMs = 60000;
      // const expiry = Date.now() + expirationMs;

      // The signature will be computed for the pathname and the expiry timestamp.
      // The two fields must be separated or padded to ensure that an attacker
      // will not be able to use the same signature for other pathname/expiry pairs.
      // The @ symbol is guaranteed not to appear in expiry, which is a (decimal)
      // number, so you can safely use it as a separator here. When combining more
      // fields, consider JSON.stringify-ing an array of the fields instead of
      // concatenating the values.
      const dataToAuthenticate = `${url.pathname}#?${url.searchParams.toString()}`;

      const mac = await crypto.subtle.sign(
        "HMAC",
        key,
        encoder.encode(dataToAuthenticate)
      );

      // `mac` is an ArrayBuffer, so you need to make a few changes to get
      // it into a ByteString, and then a Base64-encoded string.
      let base64Mac = btoa(String.fromCharCode(...new Uint8Array(mac)));

      // must convert "+" to "-" as urls encode "+" as " "
      base64Mac = base64Mac.replaceAll("+", "-");
      url.searchParams.set("s", base64Mac);

      return new Response(url.toString());
    }

    const url = new URL(request.url);
    const prefix = "/generate/";

    if (url.pathname.startsWith(prefix)) {
      // Replace the "/generate/" path prefix with "/verify/", which we
      // use in the first example to recognize authenticated paths.
      url.pathname = `/verify/${url.pathname.slice(prefix.length)}`;
      return await generateSignedUrl(url);
    }

    // You will need some super-secret data to use as a symmetric key.
    const encoder = new TextEncoder();
    const secretKeyData = encoder.encode(KEY);

    // Convert a ByteString (a string whose code units are all in the range
    // [0, 255]), to a Uint8Array. If you pass in a string with code units larger
    // than 255, their values will overflow.
    function byteStringToUint8Array(byteString: string) {
      const ui = new Uint8Array(byteString.length);
      for (let i = 0; i < byteString.length; ++i) {
        ui[i] = byteString.charCodeAt(i);
      }
      return ui;
    }

    // If the path does not begin with our protected prefix, pass the request through
    if (!url.pathname.startsWith("/verify/")) {
      return fetch(request);
    }

    // Make sure you have the minimum necessary query parameters.
    if (!url.searchParams.has(SIGNATURE_PARAM)) {
      return new Response("Missing query parameter", { status: 403 });
    }

    const key = await crypto.subtle.importKey(
      "raw",
      secretKeyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );


    const imageParams = new URLSearchParams(url.searchParams);
    imageParams.delete(SIGNATURE_PARAM);

    // Extract the query parameters we need and run the HMAC algorithm on the
    // parts of the request we are authenticating: the path and the expiration
    // timestamp. It is crucial to pad the input data, for example, by adding a symbol
    // in-between the two fields that can never occur on the right side. In this
    // case, use the @ symbol to separate the fields.
    const dataToAuthenticate = `${url.pathname}#?${imageParams.toString()}`;

    // The received MAC is Base64-encoded, so you have to go to some trouble to
    // get it into a buffer type that crypto.subtle.verify() can read.
    const receivedMacBase64 = url.searchParams.get(SIGNATURE_PARAM);
    const receivedMac = byteStringToUint8Array(atob(receivedMacBase64!));

    // Use crypto.subtle.verify() to guard against timing attacks. Since HMACs use
    // symmetric keys, you could implement this by calling crypto.subtle.sign() and
    // then doing a string comparison -- this is insecure, as string comparisons
    // bail out on the first mismatch, which leaks information to potential
    // attackers.
    const verified = await crypto.subtle.verify(
      "HMAC",
      key,
      receivedMac,
      encoder.encode(dataToAuthenticate)
    );

    if (!verified) {
      let body = "Invalid MAC";
      body += `\n\nReceived signature:\n${receivedMacBase64}`;
      body += `\n\nData:\n${dataToAuthenticate}`;
      body += `\n\nDecoded:\n${atob(receivedMacBase64!)}`
      return new Response(body, { status: 403 });
    }

		return new Response('Verified!');
	},
};
