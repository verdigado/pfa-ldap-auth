package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/mail"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode/utf8"

	_ "github.com/go-sql-driver/mysql"
	"github.com/lor00x/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
	"golang.org/x/crypto/bcrypt"
)

var (
	listenAddr     = flag.String("listen", "127.0.0.1:1389", "LDAP listen address (host:port).")
	dbDriver       = flag.String("db-driver", "mysql", "SQL driver name (mysql or postgres).")
	dbDSN          = flag.String("db-dsn", "", "Database DSN. Example MySQL: user:pass@tcp(localhost:3306)/postfixadmin")
	passwordFormat = flag.String("password-format", "", "Force a password format (cleartext|md5|sha1|bcrypt). If empty, server tries to read password_format column (if available).")
	baseDn         = flag.String("base-dn", "dc=domain,dc=example", "Base DN")
	debugMode      = flag.String("debug", "false", "Debug mode")
)

type Mailbox struct {
	Username  string
	Domain    string
	Localpart string
	Name      string
	Dn        string
}

func main() {
	flag.Parse()
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)
	server := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearch).Label("Search - Generic")
	server.Handle(routes)
	go server.ListenAndServe(string(*listenAddr))
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

func getDatabase() sql.DB {
	db, err := sql.Open(*dbDriver, *dbDSN)
	if err != nil {
		panic(err.Error())
	}
	return *db
}

func getPasswordHash(username string) string {
	var db = getDatabase()
	var password_hash string
	err := db.QueryRow("SELECT password FROM mailbox WHERE username = ?", username).Scan(&password_hash)
	if err != nil {
		log.Fatal(err)
	}
	return password_hash
}

func getMailboxes() ([]Mailbox, error) {
	var db = getDatabase()
	rows, err := db.Query("SELECT username, domain, local_part, name FROM mailbox")
	if err != nil {
		log.Print("Failed to execute query")
		return nil, err
	}
	defer rows.Close()

	var result []Mailbox
	for rows.Next() {
		var m Mailbox
		if err := rows.Scan(&m.Username, &m.Domain, &m.Localpart, &m.Name); err != nil {
			log.Print("Failed to scan query result")
			return nil, err
		}
		m.Dn, err = MailboxToDN(m.Localpart + "@" + m.Domain)
		if err != nil {
			log.Printf("Failed to get Mailbox DN: %s", err)
		}
		result = append(result, m)
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

func comparePasswordHash(username string, password string) bool {
	var password_hash string = getPasswordHash(username)
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

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	if r.AuthenticationChoice() == "simple" {
		if string(r.Name()) == "login" {
			w.Write(res)
			return
		}
		var user_password string = fmt.Sprintf("%s", r.Authentication())
		if *debugMode == "true" {
			log.Printf("Binding User=%s", string(r.Name()))
		}
		if !comparePasswordHash(string(r.Name()), user_password) {
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid credentials")
		} else {
			if *debugMode == "true" {
				log.Printf("Login succeeded.")
			}
		}
	} else {
		res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
	}
	w.Write(res)
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	if *debugMode == "true" {
		log.Printf("Request BaseDn=%s", r.BaseObject())
		log.Printf("Request Filter=%s", r.Filter())
		log.Printf("Request FilterString=%s", r.FilterString())
		log.Printf("Request Attributes=%s", r.Attributes())
		log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())
	}

	addresses, err := getMailboxes()
	if err != nil {
		log.Print("failed to get mail addresses")
	}
	for index, mailbox := range addresses {
		if mailbox.Localpart != "*" && mailbox.Localpart != "" && mailbox.Localpart != " " {
			e := ldap.NewSearchResultEntry(mailbox.Dn)
			var objectGUID = UUIDv4FromString(mailbox.Username)
			e.AddAttribute("mail", message.AttributeValue(mailbox.Username))
			e.AddAttribute("cn", message.AttributeValue(mailbox.Username))
			e.AddAttribute("displayName", message.AttributeValue(mailbox.Name))
			e.AddAttribute("objectGUID", message.AttributeValue(objectGUID))
			w.Write(e)
			if *debugMode == "true" {
				fmt.Printf("%d %s %s %s", index, mailbox.Localpart, mailbox.Domain, objectGUID)
			}
		}
		if *debugMode == "true" && index == 10 {
			break
		}
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
