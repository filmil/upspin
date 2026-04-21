## 2024-05-18 - Prevent XSS in Markdown rendering
**Vulnerability:** The documentation server reads Markdown files and renders them using `blackfriday`, casting the result to `template.HTML` which tells the Go template engine the HTML is safe and should not be escaped.
**Learning:** `blackfriday` converts Markdown to HTML but does NOT sanitize the output. If a Markdown file contains malicious HTML (like `<script>`), it would be rendered directly, leading to XSS.
**Prevention:** Always sanitize the output of Markdown parsers using a library like `bluemonday` (e.g., `bluemonday.UGCPolicy().SanitizeBytes()`) before passing the HTML to `template.HTML`.
## 2025-02-23 - Prevent internal state leakage in HTTP error responses
**Vulnerability:** HTTP handlers returning `err.Error()` directly in responses (e.g. `http.Error(w, err.Error(), ...)`), which often contains internal paths, state, or stack traces, leaking sensitive system information to end-users.
**Learning:** In the Upspin codebase, errors often encapsulate significant internal context. Passing these raw error strings directly to `http.Error` in web handlers exposes this internal structure unnecessarily. Exceptions include RPC endpoints (e.g. `rpc/server.go`) where the Upspin RPC client expects and requires the specific original error text in the response.
**Prevention:** Avoid passing `err.Error()` directly to `http.Error` in web handlers. Log the error internally (e.g. using `log.Error.Printf`) and return a generic HTTP status text (e.g. `http.StatusText(http.StatusInternalServerError)`) to the client.
