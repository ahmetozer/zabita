# Zabita

Zabita is an easy method for handling packet filtering with help of iptables and tun-tap interfaces.

## The way of work

Zabita will create a new tun interface on your system to receive a packet and return back to the system.
Iptables will drop default incoming packets and reflect the Zabita, your golang algorithm will process the packet and if it meets the requirements, systems will turn back the packet any system processes that packet instead of the real packet which comes from your real interface.

With this approach, you don't need to create lots of iptables rules or you can create dynamically manageable rules in your program which iptables are not capable to do.

## Building Main

Responsibility for the main process is creating a tunnel interface and preparing the system for handling the new packets and dynamic reloading.

```bash
go build -o zabita
```

## Buiding packet processing plugin

To achieve the dynamic reloading of the system without making binary changes to the main function, we need to compile our packet filter function separately.

Two functions are exposed to the main process, the first one is `CheckFW` which is executed when each packet arrives at the system and the other one is Main, which is execute once at the plugin load stage.

```bash
go build -buildmode=plugin -o zabita_rule.so zabita_rule.go
```

You can find more in the `/example` folder.

## Forwarding packets to zabita

You can forward all incoming packets to inspect every incoming data to your server or for lower CPU usage you can just bypass the first packet to determine connection will start or drop.

For new connections only

```bash
IPv4
iptables -t mangle -I PREROUTING -i eth0 -m conntrack --ctstate NEW -j TEE --gateway 169.254.20.255
iptables -t mangle -A PREROUTING -i eth0 -m conntrack --ctstate NEW -j DROP
# IPv6
ip6tables -t mangle -I PREROUTING -i eth0 -m conntrack --ctstate NEW -j TEE --gateway fd:900d:cafe:7a61:6269:7461::1
ip6tables -t mangle -A PREROUTING -i eth0 -m conntrack --ctstate NEW -j DROP
```

For all incoming packets

```bash
IPv4
iptables -t mangle -I PREROUTING -i eth0 -j TEE --gateway 169.254.20.255
iptables -t mangle -A PREROUTING -i eth0 -j DROP
# IPv6
iptables -t mangle -I PREROUTING -i eth0 -j TEE --gateway fd:900d:cafe:7a61:6269:7461::1
iptables -t mangle -A PREROUTING -i eth0 -j DROP
```
