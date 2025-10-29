package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	_ "github.com/go-sql-driver/mysql"
	ldap "github.com/vjeantet/ldapserver"
	"golang.org/x/crypto/bcrypt"
)

var (
	listenAddr     = flag.String("listen", "127.0.0.1:1389", "LDAP listen address (host:port).")
	dbDriver       = flag.String("db-driver", "mysql", "SQL driver name (mysql or postgres).")
	dbDSN          = flag.String("db-dsn", "", "Database DSN. Example MySQL: user:pass@tcp(localhost:3306)/postfixadmin")
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

func compareSha5123Crypt(password_hash string, password string) bool {
	//err := crypt.Crypter.Verify(password_hash, []byte(password))
	return false
}

func compareBlfCrypt(password_hash string, password string) bool {
	bcrypt.CompareHashAndPassword([]byte(password_hash), []byte(password))
	return false
}

func comparePasswordHash(username string, password string) bool {
	var password_hash string = getPasswordHash(username)
	var blf_prefix bool = strings.HasPrefix(password_hash, "{BLF-CRYPT}")
	if blf_prefix {
		return compareBlfCrypt(password_hash, password)
	} else if strings.HasPrefix(password_hash, "{SHA512-CRYPT}") {
		return compareSha5123Crypt(password_hash, password)
	}
	return false
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
		log.Printf("Binding User=%s, Pass=%s", string(r.Name()), user_password)
		if !comparePasswordHash(string(r.Name()), user_password) {
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid credentials")
		} else {
			log.Printf("Login succeeded.")
		}
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
