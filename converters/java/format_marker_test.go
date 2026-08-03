package java_converter

import "testing"

// TestFormatMarkerExactCalleeMatch is a hermetic (no JDK) regression guard for
// the builtin.format tagging in invoke: the marker must be keyed by the EXACT
// canonical FQNs in javaFormatCallees (owner is the bytecode internal name,
// java/lang/String), never a callee-name shape. A substring/suffix match would
// let a user method merely named like a JDK formatter (MyString.format,
// Helper.valueOf) claim "Args[0] is the template" semantics, wrongly prove a
// fixed host via hostFixed(), and suppress a real SSRF finding.
//
// (a) String.format / String.valueOf keep the builtin.format marker;
// (b) user methods named format/valueOf on other owners — static or virtual —
// carry NO marker.
func TestFormatMarkerExactCalleeMatch(t *testing.T) {
	strDesc := "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;"
	valDesc := "(Ljava/lang/Object;)Ljava/lang/String;"
	instrs := []dumpInstr{
		// String.format("https://h/%s", p0)
		{Op: "CONST", Cst: "https://h/%s", Line: 1},
		{Op: "LOAD", Slot: 0, Line: 1},
		{Op: "INVOKE", Kind: "INVOKESTATIC", Owner: "java/lang/String", Mname: "format", Mdesc: strDesc, Line: 1},
		{Op: "STORE", Slot: 1, Line: 1},
		// String.valueOf(p0)
		{Op: "LOAD", Slot: 0, Line: 2},
		{Op: "INVOKE", Kind: "INVOKESTATIC", Owner: "java/lang/String", Mname: "valueOf", Mdesc: valDesc, Line: 2},
		{Op: "STORE", Slot: 2, Line: 2},
		// com.example.MyString.format(...) — user class named like String
		{Op: "CONST", Cst: "https://h/%s", Line: 3},
		{Op: "LOAD", Slot: 0, Line: 3},
		{Op: "INVOKE", Kind: "INVOKESTATIC", Owner: "com/example/MyString", Mname: "format", Mdesc: strDesc, Line: 3},
		{Op: "STORE", Slot: 3, Line: 3},
		// com.example.Helper.valueOf(...) — user static named like the JDK's
		{Op: "LOAD", Slot: 0, Line: 4},
		{Op: "INVOKE", Kind: "INVOKESTATIC", Owner: "com/example/Helper", Mname: "valueOf", Mdesc: valDesc, Line: 4},
		{Op: "STORE", Slot: 4, Line: 4},
		// fmt.format(...) — user INSTANCE method named format (receiver + 1 arg)
		{Op: "LOAD", Slot: 0, Line: 5}, // receiver stand-in
		{Op: "LOAD", Slot: 0, Line: 5}, // argument
		{Op: "INVOKE", Kind: "INVOKEVIRTUAL", Owner: "com/example/Fmt", Mname: "format", Mdesc: valDesc, Line: 5},
		{Op: "STORE", Slot: 5, Line: 5},
		{Op: "RETURN", Kind: "RETURN", Line: 6},
	}
	fn := convertMethod("X", dumpMethod{Name: "h", Descriptor: "(Ljava/lang/String;)V", Static: true, Instrs: instrs}, "X.java")

	// callee -> intrinsic marker of its lowered CALL/INVOKE.
	marks := map[string]string{}
	for _, b := range fn.Blocks {
		for _, in := range b.Instrs {
			if in.Call != nil && in.Call.GetCallee() != "" {
				marks[in.Call.GetCallee()] = in.Intrinsic
			}
		}
	}

	requireMark := func(callee, want string) {
		t.Helper()
		got, ok := marks[callee]
		if !ok {
			t.Errorf("no call to %q found in the lowered IR (saw %v)", callee, marks)
			return
		}
		if got != want {
			t.Errorf("call to %q carries intrinsic %q, want %q", callee, got, want)
		}
	}

	requireMark("java:java/lang/String.format", "builtin.format")
	requireMark("java:java/lang/String.valueOf", "builtin.format")
	requireMark("java:com/example/MyString.format", "")
	requireMark("java:com/example/Helper.valueOf", "")
	requireMark("java:com/example/Fmt.format", "")
}
