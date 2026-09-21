package contain

import (
	"os"
	"testing"
)

// The admin CLI (internal/cli/session, checkConfigPerms) refuses a config file
// carrying any group bit, any world bit, or owner-execute, because that file
// holds the admin API token. It masks with 0o177. The installer writes the same
// file, so the two must agree: installing a mode the CLI rejects makes every
// shipped admin command fail against the shipped config, which is what happened
// with 0o640 ("restrict to 0o600 before using it as an admin API source").
//
// This asserts the installer side against the CLI's mask. If the CLI's rule
// changes, this test should be updated in the same commit as that change.
func TestConfigSecretModeSatisfiesAdminCLI(t *testing.T) {
	const adminCLIRejectMask os.FileMode = 0o177
	if modeConfigSecret&adminCLIRejectMask != 0 {
		t.Errorf("modeConfigSecret = %#o carries bits the admin CLI rejects (mask %#o); "+
			"shipped admin commands would refuse the shipped config",
			modeConfigSecret, adminCLIRejectMask)
	}
	if modeConfigSecret&0o400 == 0 {
		t.Errorf("modeConfigSecret = %#o is not owner-readable; the proxy could not read its own config", modeConfigSecret)
	}
}
