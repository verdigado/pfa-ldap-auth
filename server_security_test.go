package main

import "testing"

// TestValidateUsernameRejectsInjection guards the anchored mailbox validation:
// the gate must reject LDAP/SQL metacharacters, control bytes and malformed
// addresses while still accepting ordinary mailbox addresses.
func TestValidateUsernameRejectsInjection(t *testing.T) {
	good := []string{"user@example.com", "a.b+c@sub.example.co.uk", "x_y-z@d-e.org"}
	bad := []string{
		"'; DROP TABLE mailbox;-- @evil.com",
		")(uid=*)@x.com",
		"(|(mail=a@b.com))@c.com",
		"anything at all @x",
		"weird\x00null@x.com",
		"", "@nolocal.com", "no-at-sign", "trailing@dot.",
	}
	for _, u := range good {
		if !validateUsername(u) {
			t.Errorf("expected valid: %q", u)
		}
	}
	for _, u := range bad {
		if validateUsername(u) {
			t.Errorf("expected invalid: %q", u)
		}
	}
}

// TestSubdomainMailboxRoundTrip ensures mailboxes hosted on subdomains pass
// validation and survive the MailboxToDN <-> DnToMailbox conversion used during
// search and bind, so subdomain mailboxes authenticate end to end.
func TestSubdomainMailboxRoundTrip(t *testing.T) {
	*baseDn = "dc=example,dc=com"
	cases := []string{
		"user@example.com",
		"user@mail.example.com",
		"info@a.b.example.com",
		"sales@my-mail.example.com",
		"first.last@deep.sub.example.co.uk",
	}
	for _, mb := range cases {
		if !validateUsername(mb) {
			t.Errorf("validateUsername rejected subdomain mailbox %q", mb)
		}
		dn, err := MailboxToDN(mb)
		if err != nil {
			t.Errorf("MailboxToDN(%q) error: %v", mb, err)
			continue
		}
		got, ok := DnToMailbox(dn)
		if !ok || got != mb {
			t.Errorf("round-trip failed for %q: dn=%q got=%q ok=%v", mb, dn, got, ok)
		}
	}
}

// TestAuthStateLifecycle verifies the per-connection bind-state gate used by
// handleSearch: a connection is unauthenticated until a successful bind and
// returns to unauthenticated when cleared (e.g. on rebind).
func TestAuthStateLifecycle(t *testing.T) {
	const id = 42
	clearAuthenticated(id)
	if isAuthenticated(id) {
		t.Fatal("connection should start unauthenticated")
	}
	markAuthenticated(id)
	if !isAuthenticated(id) {
		t.Fatal("connection should be authenticated after bind")
	}
	clearAuthenticated(id)
	if isAuthenticated(id) {
		t.Fatal("connection should be unauthenticated after clear (rebind)")
	}
}
