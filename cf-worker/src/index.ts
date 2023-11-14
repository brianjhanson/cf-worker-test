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

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // You will need some super-secret data to use as a symmetric key.
    const encoder = new TextEncoder();
    const secretKeyData = encoder.encode("some-secret-key");

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

    const url = new URL(request.url);
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
      body += `\n\n${receivedMacBase64}`;
      body += `\n\n${dataToAuthenticate}`;
      return new Response(body, { status: 403 });
    }

		return new Response('Verified!');
	},
};
