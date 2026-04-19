## 2024-04-18 - Added Proper Document Structure and Language Attribute to Templates
**Learning:** Found a base template (`doc/templates/base.tmpl`) that was missing `<html lang="en">`, `<head>`, and `<body>` tags. This creates invalid HTML which can degrade the experience for assistive technologies like screen readers, which rely on the `lang` attribute for proper pronunciation and correct document structure for semantic navigation.
**Action:** Always ensure foundational layout components/templates contain standard HTML structure and the correct `lang` attribute in future implementations.

## 2024-04-19 - Used Semantic <nav> Tags for Navigation Menus
**Learning:** Found a navigation menu using a generic `<div class="menu">`. Replacing this with a semantic `<nav class="menu" aria-label="Main navigation">` provides a clear landmark for screen readers, improving accessibility and navigation for users relying on assistive technologies.
**Action:** Always prefer semantic HTML tags like `<nav>` with appropriate `aria-label` attributes over generic `<div>` tags for navigation elements in templates.
