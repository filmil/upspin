## 2024-05-18 - Prevent XSS in Markdown rendering
**Vulnerability:** The documentation server reads Markdown files and renders them using `blackfriday`, casting the result to `template.HTML` which tells the Go template engine the HTML is safe and should not be escaped.
**Learning:** `blackfriday` converts Markdown to HTML but does NOT sanitize the output. If a Markdown file contains malicious HTML (like `<script>`), it would be rendered directly, leading to XSS.
**Prevention:** Always sanitize the output of Markdown parsers using a library like `bluemonday` (e.g., `bluemonday.UGCPolicy().SanitizeBytes()`) before passing the HTML to `template.HTML`.
