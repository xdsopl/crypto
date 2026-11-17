Work in small, reviewable steps:
- One logical change per commit. Stop after each commit and wait for me.
- Do not rename anything unless I asked for that specific rename.
- Do not add, remove or reword comments unless I ask.
- Do not reformat or touch lines unrelated to the change.
- Do not start parallel or background tasks or subagents.
- If a change would touch more than ~3 files, or you're unsure about scope, ask first.
- Before editing, tell me in one or two sentences what you will change.

Third-party code:
- blake2_ref/ is the BLAKE2 reference implementation and ed25519_ref/ is the Ed25519 reference implementation from SUPERCOP. Do not edit them and do not copy their style; they are built as they are, with quirks/ filling in what they expect from the system.
- Security fixes belong in module/crypto.c, not in the reference code.

Code style (match the surrounding code; this is what module/ and quirks/ do):
- Indent with tabs, one tab per level, tab width 8. Never indent with spaces.
- Function definitions: opening brace on its own line. if/while/for/else: brace on the same line, `} else {`.
- A single-statement body gets no braces and sits on its own line, indented one level. An if/else with multi-line branches gets braces on both (see memmove() in quirks/string.c).
- Space after if/while/for, no space before the parentheses of a call. The pointer star binds to the name: `unsigned char *p`.
- Plain arithmetic has spaces around operators (`1 << 20`, `len - 1`). Address and index arithmetic is tight (`signature+32`, `az+32`).
- snake_case for functions and variables, UPPER_CASE for macros (`MLEN_MAX`).
- Comments are `/* */`, short, lowercase, and rare. Every file starts with a `/* */` header: a title line, a blank line, the copyright line. Leave headers alone.
- Validate arguments at the top of a function: one `if` per check, each with an early `return`.
- Return 0 on success and 1 on error. verify_signature() returns 0 only for a valid signature.
- Exported functions and variables get `__attribute__((visibility("default")))` on the line before.
- Everything is built with -std=c89 -pedantic for wasm32 without a libc: declarations only at the top of a block, no `//` comments, no declarations in `for`. Only use what quirks/ provides.
- Headers use `#pragma once`.
- Do not wrap or re-wrap lines. The longest existing lines are about 90 columns in module/ and quirks/, with tab = 8.
- Keep each file's ending as it is. module/crypto.c, quirks/string.c and quirks/crypto_*int32.h end right after the last line; quirks/string.h and quirks/stdio.h end with one blank line.

Commit messages (match the existing history):
- A short lowercase subject, no trailing period, under about 60 characters, saying what changed. Example: `added dlen parameter to digest message`.
- No body unless the reason is not obvious from the diff.
- No Co-Authored-By, Claude-Session or other trailers, and no links.
- Author commits as `Claude <noreply@anthropic.com>`. Never use my name or email.
