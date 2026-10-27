// The same rules as demo/policy.toml in the Agent Access Gateway project.
// Deny beats approval, approval beats allow, and no match means deny.
"use strict";

const POLICY = {
  "research-bot": [
    { tool: "list_files", resource: "*", effect: "allow" },
    { tool: "read_file", resource: "docs/*", effect: "allow", reason: "Research agents may read documentation." },
    { tool: "get_secret", resource: "*", effect: "deny", reason: "Research agents never receive credentials." },
  ],
  "deploy-bot": [
    { tool: "deploy", resource: "staging/*", effect: "allow", reason: "Staging deployments are low risk." },
    { tool: "deploy", resource: "production/*", effect: "needs_approval", reason: "Production changes need a person's approval." },
    { tool: "get_secret", resource: "secrets/staging-*", effect: "allow", reason: "Deploy agents may use staging credentials." },
    { tool: "get_secret", resource: "secrets/prod-*", effect: "needs_approval", reason: "Production credentials are released only with approval." },
    { tool: "read_file", resource: "reports/*", effect: "allow" },
  ],
};

const REQUESTS = [
  { label: "Deploy api to production", tool: "deploy", resource: "production/api" },
  { label: "Deploy api to staging", tool: "deploy", resource: "staging/api" },
  { label: "Get the production database password", tool: "get_secret", resource: "secrets/prod-db-password" },
  { label: "Get the staging database password", tool: "get_secret", resource: "secrets/staging-db-password" },
  { label: "Read docs/architecture.md", tool: "read_file", resource: "docs/architecture.md" },
  { label: "Read reports/release-notes.md", tool: "read_file", resource: "reports/release-notes.md" },
];

const WORDS = { allow: "Allowed", needs_approval: "Needs your approval", deny: "Denied" };

const glob = (pattern) => new RegExp("^" + pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$");

function evaluate(agent, tool, resource) {
  const rules = POLICY[agent];
  if (!rules) return { effect: "deny", reason: "Authentication failed: this agent has no valid token." };
  const matches = rules.filter((r) => glob(r.tool).test(tool) && glob(r.resource).test(resource));
  for (const effect of ["deny", "needs_approval", "allow"]) {
    const rule = matches.find((r) => r.effect === effect);
    if (rule) return { effect, reason: rule.reason || `Matched the rule for ${rule.tool} on ${rule.resource}.` };
  }
  return { effect: "deny", reason: "No rule allows this, so it is denied by default." };
}

const $ = (id) => document.getElementById(id);
const agentEl = $("agent"), requestEl = $("request"), decisionEl = $("decision"), reasonEl = $("reason"), approveEl = $("approve"), logEl = $("log");

REQUESTS.forEach((r, i) => requestEl.add(new Option(r.label, String(i))));

function log(agent, decision, req) {
  const time = new Date().toLocaleTimeString([], { hour12: false });
  const li = document.createElement("li");
  li.textContent = `${time}  ${agent}  ${decision}  ${req.tool} ${req.resource}`;
  logEl.append(li);
  while (logEl.children.length > 4) logEl.firstElementChild.remove();
}

function show(effect, reason) {
  decisionEl.dataset.d = effect;
  decisionEl.textContent = WORDS[effect];
  reasonEl.textContent = reason;
  approveEl.hidden = effect !== "needs_approval";
}

function check() {
  const agent = agentEl.value, req = REQUESTS[Number(requestEl.value)];
  const result = evaluate(agent, req.tool, req.resource);
  show(result.effect, result.reason);
  log(agent === "unknown" ? "unknown" : agent, result.effect, req);
}

approveEl.addEventListener("click", () => {
  const req = REQUESTS[Number(requestEl.value)];
  show("allow", "Approved by you. The approval works once, for this exact request only.");
  log(agentEl.value, "allow", req);
  agentEl.focus();
});
agentEl.addEventListener("change", check);
requestEl.addEventListener("change", check);
check();
