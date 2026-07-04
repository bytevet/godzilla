package buildpolicy

import "testing"

func TestAllowed_DefaultsOffAndTogglesWithEnv(t *testing.T) {
	t.Setenv(EnvAllowBuild, "") // ensure restoration after the test

	SetAllowed(false)
	if Allowed() {
		t.Error("build execution must be OFF by default (unset/empty env)")
	}

	SetAllowed(true)
	if !Allowed() {
		t.Error("SetAllowed(true) must enable build execution")
	}

	SetAllowed(false)
	if Allowed() {
		t.Error("SetAllowed(false) must disable build execution")
	}

	for _, v := range []string{"1", "true", "yes", "on"} {
		t.Setenv(EnvAllowBuild, v)
		if !Allowed() {
			t.Errorf("env %s=%q should enable build execution", EnvAllowBuild, v)
		}
	}
	for _, v := range []string{"0", "false", "", "no"} {
		t.Setenv(EnvAllowBuild, v)
		if Allowed() {
			t.Errorf("env %s=%q should NOT enable build execution", EnvAllowBuild, v)
		}
	}
}
