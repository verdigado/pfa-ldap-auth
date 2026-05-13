# PostfixAdmin LDAP Authentication
Export PostfixAdmin mailbox users with LDAP for authentication. This is intended synchronize mailboxes managed with PostfixAdmin to Keycloak (or other Identity Providers), that support OAuth. Keycloak can then be used for OAuth authentication for Dovecot.

## Build

To build the binary, run

```sh
go build .
```

## Usage

### SQL Authentication Back End

To provide the LDAP server, run the application:

```sh
pfa-ldap-auth --db-dsn "keycloak:changeme@tcp(localhost:3306)/postfixadmin" --base-dn "dc=example,dc=com" [--debug true]
```

The base-dn argument can be any arbitrary base DN. Use the `--help` argument to show all CLI options. To run this on a server, take a look at the [pfa-ldap.service](./pfa-ldap.service) file.

### Domain Based LDAP Authentication

Additionally, it is possible to configure LDAP authentication back ends for mail domains. The user will be searched with the mail attribute and the found DN + mail password used for a BIND. If the bind succeeds, the user is logged in. To configure LDAP for a domain, create a config file `/etc/pfa-ldap.d/example.com.yaml`:

```yaml
mail-domain: example.com
ldap-url: ldaps://ldap.example.com:389
starttls: false
base-dn: ou=people,dc=example,dc=com
bind-dn: cn=service,dc=example,dc=com
bind-password: secret
search-filter: "(mail=%m)"
```

#### Connecting via a private IP while preserving TLS verification

When the LDAP server must be reached on an internal/private address that is not the same as the public DNS record, set `server-ip` to the IP that should be used for the TCP connection. The hostname from `ldap-url` is still used as the TLS `ServerName`, so the certificate is verified against that FQDN using the operating system's trust store.

```yaml
mail-domain: example.com
ldap-url: ldaps://ldap.example.com:636
server-ip: 10.0.0.42
starttls: false
base-dn: ou=people,dc=example,dc=com
bind-dn: cn=service,dc=example,dc=com
bind-password: secret
search-filter: "(mail=%m)"
```

In this example the daemon connects to `10.0.0.42:636` but expects a certificate valid for `ldap.example.com`. `server-ip` must be an IP literal (IPv4 or IPv6) and is not valid with the `ldapi://` scheme.

## License

All files in this project are licensed with [Apache 2.0](./LICENSE).
