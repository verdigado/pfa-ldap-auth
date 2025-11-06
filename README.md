# PostfixAdmin LDAP Authentication
Export PostfixAdmin mailbox users with LDAP for authentication. This is intended synchronize mailboxes managed with PostfixAdmin to Keycloak (or other Identity Providers), that support OAuth. Keycloak can then be used for OAuth authentication for Dovecot.

## Build

To build the binary, run

```sh
go build .
```

## Usage

To provide the LDAP server, run the application:

```sh
pfa-ldap-auth --db-dsn "keycloak:changeme@tcp(localhost:3306)/postfixadmin" --base-dn "dc=example,dc=com" [--debug true]
```

The base-dn argument can be any arbitrary base DN. Use the `--help` argument to show all CLI options. To run this on a server, take a look at the [pfa-ldap.service](./pfa-ldap.service) file.

## License

All files in this project are licensed with [Apache 2.0](./LICENSE).