#! Discharge-instruction agent — untrusted a chart can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires sendInstruction — the discharge-instruction agent sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant sendInstruction

type Template = Cardiac | Diabetic | PostOp
type Decision = Send(Template) | Hold

let raw = fetch<web>  # UNTRUSTED a chart — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { sendInstruction(d) }  # act on the trusted decision only
