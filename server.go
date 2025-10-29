package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/go-sql-driver/mysql"
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
	db, err := sql.Open("mysql", "username:password@tcp(127.0.0.1:3306)/dbname")
	if err != nil {
		panic(err.Error())
	}
	return *db
}

func comparePasswordHash(username string, password string) bool {
	var db = getDatabase()
	var password_hash string
	err := db.QueryRow("SELECT username, password FROM users WHERE username = ?", username).Scan(password_hash)
	if err != nil {
		log.Fatal(err)
	}
	return true
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	if r.AuthenticationChoice() == "simple" {
		if string(r.Name()) == "login" {
			w.Write(res)
			return
		}
		var user_password string = fmt.Sprintf("%#v", r.Authentication())
		log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), user_password)
		comparePasswordHash(string(r.Name()), user_password)
		res.SetResultCode(ldap.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")
	} else {
		res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
	}
	w.Write(res)
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

	select {
	case <-m.Done:
		log.Print("Leaving handleSearch...")
		return
	default:
	}

	e := ldap.NewSearchResultEntry("cn=mail@test.example," + string(r.BaseObject()))
	e.AddAttribute("mail", "mail@test.example")
	e.AddAttribute("cn", "Test User")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)

}
