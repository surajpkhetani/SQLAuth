# SQLAuth
SQL Authenticator and Enumerator

An SQL Authentication tool that tests for integrated SQL authentication and runs multiple checks for privilege escalation. It takes an input containing a mapping of SQL servers and ports in the format IP:PORT.

```
SQLAuth.exe list.txt
```
list.txt should contain servers in below format

127.0.0.1:1433

1.1.1.1:1499

.

.

.
