package main

import (
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	ldapclient "github.com/go-ldap/ldap/v3"
	_ "github.com/go-sql-driver/mysql"
	"github.com/lor00x/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type LDAPServer struct {
	db *sql.DB
}

var (
	listenAddr     = flag.String("listen", "127.0.0.1:1389", "LDAP listen address (host:port).")
	dbDriver       = flag.String("db-driver", "mysql", "SQL driver name (mysql or postgres).")
	dbDSN          = flag.String("db-dsn", "", "Database DSN. Example MySQL: user:pass@tcp(localhost:3306)/postfixadmin")
	passwordFormat = flag.String("password-format", "", "Force a password format (cleartext|md5|sha1|bcrypt). If empty, server tries to read password_format column (if available).")
	baseDn         = flag.String("base-dn", "dc=domain,dc=example", "Base DN")
	debugMode      = flag.String("debug", "false", "Debug mode")
	configDir      = flag.String("config-dir", "/etc/pfa-ldap.d", "Directory containing per-domain LDAP backend config files (*.yaml / *.yml).")
)

// LDAPBackendConfig holds the configuration for one upstream LDAP backend,
// loaded from a YAML file in the config directory.
//
// TLS mode is selected via the ldap-url scheme:
//   - ldap://  — plaintext (optionally upgraded via starttls: true)
//   - ldaps:// — implicit TLS (port 636)
//   - ldapi:// — Unix socket
type LDAPBackendConfig struct {
	MailDomain   string `yaml:"mail-domain"`
	LDAPUrl      string `yaml:"ldap-url"`
	ServerIP     string `yaml:"server-ip"`
	StartTLS     bool   `yaml:"starttls"`
	BaseDN       string `yaml:"base-dn"`
	BindDN       string `yaml:"bind-dn"`
	BindPassword string `yaml:"bind-password"`
	SearchFilter string `yaml:"search-filter"`
	// DisableSQLFallback, when true, prevents the daemon from falling back to
	// SQL authentication for this domain if the LDAP bind fails or the user
	// is not present in the upstream directory. Defaults to false, which
	// preserves the historic behaviour of trying SQL after LDAP.
	DisableSQLFallback bool `yaml:"disable-sql-fallback"`
}

// ldapBackends maps lower-cased mail domain → LDAPBackendConfig.
// Populated at startup from --config-dir; never written after that.
var ldapBackends map[string]LDAPBackendConfig

// loadBackendConfigs reads all *.yaml / *.yml files from dir and populates
// ldapBackends. Missing directory is treated as a warning, not a fatal error.
func loadBackendConfigs(dir string) {
	ldapBackends = make(map[string]LDAPBackendConfig)

	patterns := []string{filepath.Join(dir, "*.yaml"), filepath.Join(dir, "*.yml")}
	var files []string
	for _, p := range patterns {
		matches, err := filepath.Glob(p)
		if err != nil {
			log.Printf("Warning: error globbing %s: %v", p, err)
			continue
		}
		files = append(files, matches...)
	}

	if len(files) == 0 {
		log.Printf("No backend config files found in %s", dir)
		return
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("Warning: could not read backend config %s: %v", f, err)
			continue
		}
		var cfg LDAPBackendConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Printf("Warning: could not parse backend config %s: %v", f, err)
			continue
		}
		if cfg.MailDomain == "" {
			log.Printf("Warning: backend config %s has no mail-domain, skipping", f)
			continue
		}
		if cfg.ServerIP != "" {
			if net.ParseIP(cfg.ServerIP) == nil {
				log.Printf("Warning: backend config %s has invalid server-ip %q, ignoring", f, cfg.ServerIP)
				cfg.ServerIP = ""
			}
		}
		domain := strings.ToLower(cfg.MailDomain)
		if _, exists := ldapBackends[domain]; exists {
			log.Printf("Warning: duplicate mail-domain %q in file %s (already loaded)", domain, f)
			continue
		}
		ldapBackends[domain] = cfg
		log.Printf("Loaded LDAP backend for domain %q from %s", domain, f)
	}
}

// dialBackend dials the upstream LDAP server described by cfg. When
// cfg.ServerIP is set, the TCP connection target is rewritten to that IP, but
// the TLS ServerName remains the hostname from cfg.LDAPUrl so the certificate
// is verified against the FQDN using the operating system's trust store. The
// returned *tls.Config is reused by STARTTLS so the same ServerName applies on
// upgrade.
func dialBackend(cfg LDAPBackendConfig) (*ldapclient.Conn, *tls.Config, error) {
	u, err := url.Parse(cfg.LDAPUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ldap-url %q: %w", cfg.LDAPUrl, err)
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch scheme {
		case "ldap":
			port = "389"
		case "ldaps":
			port = "636"
		}
	}

	tlsCfg := &tls.Config{ServerName: host}

	dialURL := cfg.LDAPUrl
	if cfg.ServerIP != "" {
		if scheme == "ldapi" {
			return nil, nil, fmt.Errorf("server-ip is not valid with ldapi:// scheme")
		}
		hostPart := cfg.ServerIP
		if strings.Contains(hostPart, ":") {
			// IPv6 literal needs brackets inside a URL authority.
			hostPart = "[" + hostPart + "]"
		}
		dialURL = fmt.Sprintf("%s://%s:%s", scheme, hostPart, port)
	}

	conn, err := ldapclient.DialURL(dialURL, ldapclient.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", dialURL, err)
	}
	return conn, tlsCfg, nil
}

// authenticateViaLDAP authenticates email/password against an upstream LDAP
// server described by cfg. It follows the search-then-bind pattern:
//  1. Dial the upstream server (with TLS / STARTTLS as configured).
//  2. Bind with the service account (bind-dn / bind-password).
//  3. Search for the user using search-filter (%m replaced by full email).
//  4. Bind with the found DN and the client-provided password.
func authenticateViaLDAP(cfg LDAPBackendConfig, email, password string) (bool, error) {
	if password == "" {
		return false, nil
	}
	conn, tlsCfg, err := dialBackend(cfg)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if *debugMode == "true" && cfg.ServerIP != "" {
		log.Printf("LDAP backend: dialing %s (TLS ServerName=%s)", cfg.ServerIP, tlsCfg.ServerName)
	}

	if cfg.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			return false, fmt.Errorf("starttls %s: %w", cfg.LDAPUrl, err)
		}
	}

	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return false, fmt.Errorf("service bind as %s: %w", cfg.BindDN, err)
	}

	filter := strings.ReplaceAll(cfg.SearchFilter, "%m", ldapclient.EscapeFilter(email))
	searchReq := ldapclient.NewSearchRequest(
		cfg.BaseDN,
		ldapclient.ScopeWholeSubtree,
		ldapclient.NeverDerefAliases,
		2,
		0,
		false,
		filter,
		[]string{"dn"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil {
		return false, fmt.Errorf("search for %s: %w", email, err)
	}
	if len(sr.Entries) == 0 {
		if *debugMode == "true" {
			log.Printf("LDAP backend: no entry found for %s with filter %s", email, filter)
		}
		return false, nil
	}
	if len(sr.Entries) > 1 {
		return false, fmt.Errorf("ambiguous search: %d entries found for %s", len(sr.Entries), email)
	}
	userDN := sr.Entries[0].DN

	if err := conn.Bind(userDN, password); err != nil {
		if *debugMode == "true" {
			log.Printf("LDAP backend: bind failed for DN %s: %v", userDN, err)
		}
		return false, nil
	}
	return true, nil
}

type Mailbox struct {
	Dn         string
	Username   string
	Domain     string
	Localpart  string
	Name       string
	objectGUID string
}

type MailboxList struct {
	UUID    string
	Mailbox string
}

var mailboxMap []MailboxList

var ldap_attributes_map = map[string]string{
	"objectGUID": "objectGUID",
	"cn":         "username",
	"mail":       "username",
}

func addMailboxMapEntry(uuid, mailbox string) {
	mailboxMap = append(mailboxMap, MailboxList{UUID: uuid, Mailbox: mailbox})
}

func getMailboxMapEntry(uuid string) (string, bool) {
	for _, e := range mailboxMap {
		if strings.HasPrefix(e.UUID, uuid) {
			return e.Mailbox, true
		}
	}
	return "", false
}

func deleteMailboxMapEntry(uuid string) bool {
	for i, e := range mailboxMap {
		if e.UUID == uuid {
			mailboxMap = append(mailboxMap[:i], mailboxMap[i+1:]...)
			return true
		}
	}
	return false
}

func initializeObjectGuidCache(db *sql.DB) {
	getDbMailboxes(db, "") // Initialize UUID Map
	log.Printf("Length of objectGUID map: %d", len(mailboxMap))
}

func initializeServer(db *sql.DB) ldap.Server {

	srv := &LDAPServer{db: db}
	server := ldap.NewServer()
	routes := ldap.NewRouteMux()
	routes.Bind(srv.handleBind)
	routes.Search(srv.handleSearch)
	server.Handle(routes)
	return *server
}

func main() {
	flag.Parse()
	if *debugMode == "true" {
		ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)
	} else {
		ldap.Logger = ldap.DiscardingLogger
	}
	loadBackendConfigs(*configDir)
	db := getDatabase()
	defer db.Close()
	initializeObjectGuidCache(db)
	server := initializeServer(db)
	go reapAuthedConns()
	go server.ListenAndServe(string(*listenAddr))
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)
	server.Stop()
}

// usernameRe matches a syntactically valid mailbox address: a non-empty local
// part of conservative characters, an '@', and a domain with at least one dot
// and a 2+ character TLD. It is fully anchored so the whole string must match —
// the previous unanchored pattern accepted any string that merely contained an
// '@', which let crafted values (LDAP/SQL metacharacters, control bytes, empty
// local parts) pass the validation gate.
var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

func validateUsername(username string) bool {
	return usernameRe.MatchString(username)
}

func getDatabase() *sql.DB {
	db, err := sql.Open(*dbDriver, *dbDSN)
	if err != nil {
		panic(err.Error())
	}
	return db
}

func getPasswordHash(db *sql.DB, username string) (string, error) {
	var password_hash string
	err := db.QueryRow("SELECT password FROM mailbox WHERE username = ?", username).Scan(&password_hash)
	if err != nil {
		return "", err
	}
	return password_hash, nil
}

func GenerateSqlQuery(filter string) (string, []any, error) {
	filter_key, filter_value, filter_err := ExtractFilter(filter)
	var exact_match bool = false

	if filter_key == "objectGUID" {
		new_filter_value, exists := getMailboxMapEntry(filter_value)
		if !exists {
			log.Printf("Could not map objectGUID %s to username.", filter_value)
			return "", nil, errors.New("could not find objectGUID")
		}
		filter_value = new_filter_value
		filter_key = "username"
		exact_match = true
	}

	var query string
	var args []any
	if filter_err == nil && filter != "" && !exact_match {
		query = "SELECT username, domain, local_part, name FROM mailbox WHERE " + filter_key + " LIKE ?"
		args = []any{"%" + filter_value + "%"}
	} else if filter_err == nil && filter != "" && exact_match {
		query = "SELECT username, domain, local_part, name FROM mailbox WHERE " + filter_key + " = ?"
		args = []any{filter_value}
	} else {
		query = "SELECT username, domain, local_part, name FROM mailbox"
	}
	if *debugMode == "true" {
		log.Printf("Query: %s", query)
	}
	return query, args, nil
}

func processMailboxRow(m Mailbox) (Mailbox, bool) {
	var err error
	if !validateUsername(m.Username) {
		log.Printf("Invalid Username: %s", m.Username)
		return m, false
	}
	m.Dn, err = MailboxToDN(m.Username)
	if err != nil {
		log.Printf("Failed to get Mailbox DN (%s): %s", m.Username, err)
		return m, false
	}
	if m.Localpart != "*" && m.Localpart != "" && m.Localpart != " " {
		m.objectGUID = UUIDv4FromString(m.Username)
		addMailboxMapEntry(m.objectGUID, m.Username)
	} else {
		log.Printf("Failed to UUID (%s): %s", m.Username, err)
		return m, false
	}
	if *debugMode == "true" {
		log.Printf("%s %s %s", m.Username, m.objectGUID, m.Dn)
	}
	return m, true
}

func getDbMailboxes(db *sql.DB, filter string) ([]Mailbox, error) {
	var result []Mailbox
	query, args, err := GenerateSqlQuery(filter)
	if err != nil {
		return result, err
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Print("Failed to execute query")
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var m Mailbox
		if err := rows.Scan(&m.Username, &m.Domain, &m.Localpart, &m.Name); err != nil {
			log.Print("Failed to scan query row")
			continue
		}
		processed_mailbox, success := processMailboxRow(m)
		if success {
			result = append(result, processed_mailbox)
		}
	}
	if err := rows.Err(); err != nil {
		log.Print("Error in result")
		return nil, err
	}
	return result, nil
}

func compareSha512Crypt(password_hash string, password string) bool {
	//err := crypt.Crypter.Verify(password_hash, []byte(password))
	return false
}

func compareBlfCrypt(password_hash string, password string) bool {
	password_hash = strings.TrimPrefix(password_hash, "{BLF-CRYPT}")
	err := bcrypt.CompareHashAndPassword([]byte(password_hash), []byte(password))
	return err == nil
}

func comparePasswordHash(db *sql.DB, username string, password string) bool {
	password_hash, err := getPasswordHash(db, username)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("Error fetching password hash for %s: %v", username, err)
		}
		return false
	}
	var validated = false
	if strings.HasPrefix(password_hash, "{BLF-CRYPT}") {
		validated = compareBlfCrypt(password_hash, password)
	} else if strings.HasPrefix(password_hash, "{SHA512-CRYPT}") {
		validated = compareSha512Crypt(password_hash, password)
	}
	if *debugMode == "true" {
		log.Printf("Password hash validates for user %s: %t", username, validated)
	}
	return validated
}

func DnToMailbox(dn string) (string, bool) {
	dn_parts := strings.Split(dn, ",")
	base_parts := strings.Split(*baseDn, ",")
	// Strip the base DN suffix from the end of the DN parts.
	if len(dn_parts) <= len(base_parts) {
		return "", false
	}
	tail := dn_parts[len(dn_parts)-len(base_parts):]
	for i, p := range tail {
		if !strings.EqualFold(p, base_parts[i]) {
			return "", false
		}
	}
	dn_parts = dn_parts[:len(dn_parts)-len(base_parts)]
	localpart, dn_parts := dn_parts[0], dn_parts[1:]
	localpart = strings.TrimPrefix(localpart, "cn=")
	for i := 0; i < len(dn_parts); i++ {
		dn_parts[i] = strings.TrimPrefix(dn_parts[i], "dc=")
	}
	username := localpart + "@" + strings.Join(dn_parts, ".")
	if validateUsername(username) {
		return username, true
	}
	return "", false
}

// authedConns tracks LDAP connections that have completed a successful simple
// bind, keyed by the per-connection Numero assigned by the ldapserver library.
// handleSearch refuses to serve directory entries to connections that are not
// present here, so an unauthenticated peer cannot enumerate every mailbox.
//
// The ldapserver library exposes no connection-close callback, so entries
// cannot be removed deterministically on disconnect. Instead each entry records
// the time of the connection's last request; reapAuthedConns periodically drops
// entries idle longer than authIdleTimeout. A connection that closed will never
// refresh its entry and is reaped; an active connection refreshes it on every
// request. The map therefore stays bounded by the number of recently-active
// connections rather than growing for the lifetime of the process.
const authIdleTimeout = 1 * time.Hour

var (
	authedMu    sync.Mutex
	authedConns = make(map[int]time.Time)
)

func markAuthenticated(numero int) {
	authedMu.Lock()
	authedConns[numero] = time.Now()
	authedMu.Unlock()
}

func clearAuthenticated(numero int) {
	authedMu.Lock()
	delete(authedConns, numero)
	authedMu.Unlock()
}

// isAuthenticated reports whether the connection has a live successful bind and,
// as a side effect, refreshes its idle timer so active connections are not
// reaped.
func isAuthenticated(numero int) bool {
	authedMu.Lock()
	defer authedMu.Unlock()
	if _, ok := authedConns[numero]; !ok {
		return false
	}
	authedConns[numero] = time.Now()
	return true
}

func reapAuthedConns() {
	for {
		time.Sleep(authIdleTimeout)
		cutoff := time.Now().Add(-authIdleTimeout)
		authedMu.Lock()
		for numero, seen := range authedConns {
			if seen.Before(cutoff) {
				delete(authedConns, numero)
			}
		}
		authedMu.Unlock()
	}
}

func (s *LDAPServer) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	username := string(r.Name())

	// Any (re)bind attempt invalidates a previously authenticated state on this
	// connection so a failed or anonymous rebind cannot retain access.
	clearAuthenticated(m.Client.Numero)

	if r.AuthenticationChoice() == "simple" {
		mailbox, valid_dn := DnToMailbox(username)
		if !valid_dn {
			log.Printf("Invalid DN: %s", username)
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid credentials")
		} else {
			user_password := fmt.Sprintf("%s", r.Authentication())
			if *debugMode == "true" {
				log.Printf("Binding User: %s", mailbox)
			}

			// Extract the mail domain to check for a dedicated LDAP backend.
			var authenticated bool
			var triedLDAPBackend bool
			var sqlFallbackDisabled bool
			var authDomain string
			atIdx := strings.LastIndex(mailbox, "@")
			if atIdx >= 0 {
				authDomain = strings.ToLower(mailbox[atIdx+1:])
				if backend, ok := ldapBackends[authDomain]; ok {
					triedLDAPBackend = true
					sqlFallbackDisabled = backend.DisableSQLFallback
					if *debugMode == "true" {
						log.Printf("Using LDAP backend for domain %q", authDomain)
					}
					ok, err := authenticateViaLDAP(backend, mailbox, user_password)
					if err != nil {
						log.Printf("LDAP backend error for %s: %v", mailbox, err)
					}
					authenticated = ok
				}
			}

			// Determine which backend produced the result. SQL is used either
			// when no LDAP backend is configured for the domain, or as a
			// fallback when the LDAP backend rejected the credentials / failed
			// — unless the backend has disable-sql-fallback: true.
			var backend string
			switch {
			case authenticated:
				backend = "LDAP (" + authDomain + ")"
			case triedLDAPBackend && sqlFallbackDisabled:
				if *debugMode == "true" {
					log.Printf("LDAP backend rejected %s, SQL fallback disabled for domain %q", mailbox, authDomain)
				}
				backend = "LDAP (" + authDomain + ")"
			default:
				if triedLDAPBackend && *debugMode == "true" {
					log.Printf("LDAP backend rejected %s, falling back to SQL", mailbox)
				}
				authenticated = comparePasswordHash(s.db, mailbox, user_password)
				if triedLDAPBackend {
					backend = "SQL (fallback from LDAP " + authDomain + ")"
				} else {
					backend = "SQL"
				}
			}

			if authenticated {
				markAuthenticated(m.Client.Numero)
				log.Printf("Authentication successful: email=%s backend=%s", mailbox, backend)
			} else {
				log.Printf("Authentication failed: email=%s backend=%s", mailbox, backend)
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				res.SetDiagnosticMessage("invalid credentials")
			}
		}
	} else {
		res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
	}
	w.Write(res)
}

func ExtractFilter(filter string) (string, string, error) {
	for attr_name, sql_name := range ldap_attributes_map {
		attr_value, err := ExtractFilterValue(attr_name, filter)
		if err != nil {
			continue
		}
		return sql_name, attr_value, nil
	}
	return "", "", errors.New("could not identify an attribute for filtering")
}

func ExtractFilterValue(attribute string, filter string) (string, error) {
	var mailRe = regexp.MustCompile(attribute + "=([^)]+)")
	if m := mailRe.FindStringSubmatch(filter); len(m) > 1 {
		return strings.Replace(m[1], "*", "", 2), nil
	}
	return "", errors.New("attribute not round")
}

func (s *LDAPServer) handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	// Require a successful bind on this connection before returning any mailbox
	// data; otherwise an unauthenticated peer could enumerate the directory.
	if !isAuthenticated(m.Client.Numero) {
		log.Printf("Rejecting unauthenticated search from %s", m.Client.Addr())
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultInsufficientAccessRights)
		w.Write(res)
		return
	}

	if *debugMode == "true" {
		log.Printf("Request FilterString=%s", r.FilterString())
	}
	addresses, err := getDbMailboxes(s.db, r.FilterString())
	if err != nil {
		log.Printf("failed to get mail addresses. Filter: '%s'", r.FilterString())
	} else {
		log.Printf("Received %d results", len(addresses))
	}
	for _, mailbox := range addresses {
		e := ldap.NewSearchResultEntry(mailbox.Dn)
		e.AddAttribute("mail", message.AttributeValue(mailbox.Username))
		e.AddAttribute("cn", message.AttributeValue(mailbox.Username))
		e.AddAttribute("displayName", message.AttributeValue(mailbox.Name))
		e.AddAttribute("objectGUID", message.AttributeValue(mailbox.objectGUID))
		e.AddAttribute("domain", message.AttributeValue(mailbox.Domain))
		e.AddAttribute("localpart", message.AttributeValue(mailbox.Localpart))
		w.Write(e)
	}
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func MailboxToDN(mailbox string) (string, error) {
	addr, err := mail.ParseAddress(mailbox)
	if err != nil {
		return "", fmt.Errorf("invalid mailbox %q: %w", mailbox, err)
	}
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("mailbox %q does not contain exactly one '@'", mailbox)
	}
	local, domain := parts[0], parts[1]
	if local == "" {
		return "", errors.New("local part (before '@') is empty")
	}
	if domain == "" {
		return "", errors.New("domain part (after '@') is empty")
	}
	cn := escapeDNValue(local)
	domainLabels := strings.Split(domain, ".")
	if len(domainLabels) == 0 {
		return "", errors.New("domain does not contain any label")
	}
	var dcParts []string
	for _, l := range domainLabels {
		if l == "" {
			return "", fmt.Errorf("empty label in domain %q", domain)
		}
		dcParts = append(dcParts, fmt.Sprintf("dc=%s", escapeDNValue(l)))
	}
	dn := fmt.Sprintf("cn=%s", cn)
	if len(dcParts) > 0 {
		dn = dn + "," + strings.Join(dcParts, ",") + "," + *baseDn
	}
	return dn, nil
}

func escapeDNValue(s string) string {
	if s == "" {
		return ""
	}

	var b strings.Builder
	runes := []rune(s)

	if runes[0] == ' ' {
		b.WriteByte('\\')
	}
	if runes[len(runes)-1] == ' ' {
		defer func() {
			b.WriteByte('\\')
		}()
	}

	for _, r := range runes {
		switch r {
		case ',', '+', '"', '\\', '<', '>', ';', '#', '=', ' ':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			if r < 0x20 || r > 0x7e {
				utf8Buf := make([]byte, utf8.RuneLen(r))
				utf8.EncodeRune(utf8Buf, r)
				for _, c := range utf8Buf {
					fmt.Fprintf(&b, "\\%02X", c)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func UUIDv4FromString(s string) string {
	h := sha256.Sum256([]byte(s))
	u := h[:16]
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	hexStr := hex.EncodeToString(u)
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexStr[0:8],
		hexStr[8:12],
		hexStr[12:16],
		hexStr[16:20],
		hexStr[20:32])
}
