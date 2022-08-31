# Allow IP by DNS Query

In this example,
You will be able to access the SSH server from IPv4 and IPv6 from anywhere without any restriction.
ICMP (ping) is forbidden in both IPv4 and IPv6.
Wireguard is only allowed for IPv4.
Other ports will be allowed if you execute nslookup to your server.

```bash
nslookup mySecRet.value.zabita.ahmet.engineer ${yourserverip}
```

To build this example

```bash
go build -buildmode=plugin -o zabita_rule.so zabita_rule.go
mv zabita_rule.so /lib
```

After this changes, zabita will be load your rules.
