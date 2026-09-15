package llm

// providers.go is the ONLY place in this package that knows "claude" or
// "codex" exist. command.go and reviewer.go are generic over the Provider
// table; a third agent CLI is a table entry (here, or in Options.Providers /
// a .godzilla.yaml `llm.providers:` block), never a Go change.

// builtinProviders is the default command-backend table, tried in this order
// by the auto ladder (reviewer.go's Select) once neither HTTP backend has
// credentials. Verified on the reference machine: claude 2.1.272 and codex
// 0.154.0; both Probe commands exit 0 and invoke no model, so running one on
// every scan that reaches this rung costs nothing.
//
// --allowedTools/--sandbox read-only fix an agreed READ-ONLY posture for the
// reviewer (see command.go's security note): a user who overrides Command in
// their own config overrides that posture too — their machine, their call —
// but the shipped default must not be able to write.
var builtinProviders = []Provider{
	{
		Name: "claude",
		// Stdin, not a "{prompt}" argument: --allowedTools is VARIADIC
		// (`--allowedTools <tools...>`), so a trailing prompt is swallowed as
		// another tool name and claude answers `Ignoring --allowedTools rule
		// "<the prompt>"` and exits 1 — every review failing.
		Command:       []string{"claude", "-p", "--allowedTools", "Read,Grep,Glob"},
		Stdin:         true,
		Probe:         []string{"claude", "auth", "status"},
		ProbeContains: `"loggedIn": true`,
	},
	{
		Name:    "codex",
		Command: []string{"codex", "exec", "--sandbox", "read-only", "--skip-git-repo-check", "{prompt}"},
		Probe:   []string{"codex", "login", "status"},
	},
}
