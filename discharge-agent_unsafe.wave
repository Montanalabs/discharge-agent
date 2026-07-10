#! VULNERABLE discharge-agent — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant sendInstruction

let raw = fetch<web>
privileged { sendInstruction(raw) }  # tainted -> tool: REJECTED
