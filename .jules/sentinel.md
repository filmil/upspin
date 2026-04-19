## 2024-05-18 - Prevent XSS in Markdown rendering
**Vulnerability:** The documentation server reads Markdown files and renders them using `blackfriday`, casting the result to `template.HTML` which tells the Go template engine the HTML is safe and should not be escaped.
**Learning:** `blackfriday` converts Markdown to HTML but does NOT sanitize the output. If a Markdown file contains malicious HTML (like `<script>`), it would be rendered directly, leading to XSS.
**Prevention:** Always sanitize the output of Markdown parsers using a library like `bluemonday` (e.g., `bluemonday.UGCPolicy().SanitizeBytes()`) before passing the HTML to `template.HTML`.

## 2024-05-18 - Prevent exposing stack traces in HTTP error responses
**Vulnerability:** HTTP handlers were passing `err.Error()` directly to `http.Error()` on 500 Internal Server Errors, which leaked internal error details, paths, and potentially stack traces to clients.
**Learning:** Returning `err.Error()` in Go web handlers directly to the client can expose sensitive backend state when handling internal logic errors (e.g. from `pb.Marshal` or Upspin `errors` which encode deep context).
**Prevention:** Catch the error internally, log it via `log.Error.Printf`, and return a generic `http.StatusText(http.StatusInternalServerError)` to the client to maintain security.
