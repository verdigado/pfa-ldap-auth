package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

var (
	listenAddr     = flag.String("listen", "127.0.0.1:1389", "LDAP listen address (host:port).")
	baseDN         = flag.String("baseDN", "dc=example,dc=com", "Base DN for your LDAP tree.")
	dbDriver       = flag.String("db-driver", "mysql", "SQL driver name (mysql or postgres).")
	dbDSN          = flag.String("db-dsn", "", "Database DSN. Example MySQL: user:pass@tcp(localhost:3306)/postfixadmin")
	bindAttr       = flag.String("bind-attr", "uid", "DN attribute to use as username (e.g. uid, mail, cn). For binds, server will extract this from Bind DN.")
	userQuery      = flag.String("user-query", "", "SQL query to fetch user. Use one parameter placeholder. Default depends on driver.")
	passwordFormat = flag.String("password-format", "", "Force a password format (cleartext|md5|sha1|bcrypt). If empty, server tries to read password_format column (if available).")
)

func main() {
	flag.Parse()
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)
	server := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	server.Handle(routes)
	go server.ListenAndServe(string(*listenAddr))
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if string(r.Name()) == "myLogin" {
		w.Write(res)
		return
	}

	log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}
