# Module 11 — Design Decisions

## D1: OOB receiver returns a 1×1 transparent GIF (not JSON)
Real OOB beacons use `<img src="...">` to fire across origins without CORS restrictions. An img tag does not care about the response content type — but if the server returned an error status, some browsers suppress the `onerror` handler. Returning a valid GIF with `image/gif` keeps the beacon silent and prevents the `onerror` from firing unexpectedly. This models the exact technique used by XSS Hunter and Burp Collaborator.

## D2: /log-viewer renders entries without any sanitisation
The pedagogical point of blind XSS is that the *storage* surface looks safe (a logging endpoint) while the *rendering* surface is the actual sink. Sanitising either endpoint would destroy the lesson. The intentional unsanitised rendering is what makes /log-viewer the sink — students must recognise that privilege-separated rendering surfaces (admin panels, log dashboards, PDF generators) are sinks just as much as a reflected search box.

## D3: /pdf-preview and /email-preview are GET endpoints with query parameters
In real applications these would be POST endpoints with a request body. Using GET with query parameters lets students construct attack URLs directly in the browser address bar and share them as demonstration links — consistent with how reflected XSS PoCs are shared. The DECISIONS.md for prior modules make the same choice for /reflect.

## D4: OOB log stores IP, User-Agent, Referer, Origin, and query params
This mirrors exactly what a real blind XSS callback server captures. Students need to understand what information a payload leaks even without explicit exfiltration — the browser sends UA, Referer, and Origin automatically with every request. The lab makes this visible so the threat model in the PhD paper can enumerate what a zero-interaction OOB beacon reveals by default.

## D5: Log entries are stored as raw strings; no level validation
Accepting any `level` value and any `message` string without validation models real logging libraries that trust their callers. This allows students to inject payloads into the level field as well, not just the message — demonstrating that every field that reaches a rendered surface is a potential XSS vector, not just the "obvious" text content field.
