# Coding guidelines

* Prioritize code correctness and clarity. Speed and efficiency are secondary priorities unless otherwise specified.
* Prefer implementing functionality in existing files unless it is a new logical component. Avoid creating many small files.
* Before writing UI code, inspect the site's theme, styles, and existing components. Reuse established patterns so new UI fits the rest of the site.
* Avoid writing code that silently discards errors that breaks something in the program.
* Make errors useful for debugging: identify the failed operation and relevant resource, preserve the underlying error details, and never expose secrets.
* If you find any bad code or technical debt, fix it if very simple or tell it. Do not ignore it or quietly add a feature on top of it.
* Do not write "because why not" code. Ex: `from __future__ import annotations` that is not needed, module docstring that bring no value, shebang on a file which is never called directly...
* In python code, write return types on functions, except when they return None
* Do not unnecessarily add complexity to the codebase. If a simpler solution is also good, use it.
* Startup code may bring stored state up to the current schema. Mark the function and its only call with `// COMPAT`. Running it again on state that is already current must leave that state unchanged. Every `// COMPAT` will be deleted before publication.
* Do not keep two paths, one for the previous stored shape and one for the current one. A `// COMPAT` function is the only code that may see the old shape, and only at startup. After it runs, every reader uses the current schema. No fallback when an old column or field is missing, no second query, and no parser that still accepts the old format.
* If a migration would discard stored data, do not write it. Fail startup and give the operator the command to run.
* Do not write characters that are not writable with a keyboard (e.g. `—` or `…`) in code, comments or doc.
* Do not write tests if no one asked for it.

## Comments

Do not write organizational or comments that summarize the code.
Comments should only be written if they add real value to the code, for example:

* Comments that explain "why" the code is written in some way in the case there is a reason that is tricky / non-obvious.

* Comments that provide important information that otherwise would not have been obvious

`// COMPAT` is the marker for a startup migration. Keep it on the function and its call until both are removed.

## Agent prompt

`agent/PROMPT.md` is the runtime contract for every Pamphagos agent, not general
documentation or a security-testing methodology.

* Add an instruction only when it is broadly applicable to Pamphagos sessions and
  omitting it would commonly cause unsafe, incorrect, or unusable behavior.
* Keep reusable testing methodology and mutable operational knowledge in Knowledge.
  Keep detailed tool usage in the tool's own help or documentation.
* Do not duplicate documentation in the prompt. Direct the agent to the
  authoritative source when it can discover the information reliably.
* Keep instructions independent of a particular agent runtime when the required
  outcome is portable.
* Do not assume optional services, Knowledge content, mounts, or tools are always
  available.
* Verify current behavior before documenting it. Remove obsolete instructions
  instead of adding exceptions around them.
* Keep the prompt concise. When adding an instruction, look for wording that can
  replace or simplify existing text instead of only appending more text.
* After changing the prompt, read it as a whole and check for duplicated,
  contradictory, or ambiguous instructions.
