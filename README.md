vyatta-iptables
===============

Vyatta configuration templates and scripts to support low level access to
iptables and ipsets.

Because this module is intended to be self contained it will disable itself
if any of the standard modules that interact with iptables are enabled, these
are:
	firewall
	port-forward
	zone-policy
	service webproxy
	system conntrack
	service nat

Basic variables are supported which allows for expansion in iptables
rules. If a variable contains multiple items the rule will be duplicated for
each item. Multiple multi-variables can be used.

Some standard "options" are also supported to provide similar functionality
to the original firewall.

"protected-update" can be enabled on the system chains and this will cause
the policy to be set to ACCEPT before any changes are made, that way if there
are failures during the commit it is less likely to result in a locked out
system. This is good to use on the filter/INPUT chain.

Configuration commands:

	iptables
		ipset <name>
			type <see "ipset help" for types>
			item <value>
			item <value>
		filter
			policy <ACCEPT|REJECT|DROP>
			protected-update <enable|disable>
			chain <name>
				rule <number>
					desc <text description>
					exec <ip tables command line>
		variable <name>
			value <value>
	option
		send-redirects <enable|disable>
		log-martians <enable|disable>
		all-ping <enable|disable>
		broadcast-ping <enable|disable>
		ip-src-route <enable|disable>
		receive-redirects <enable|disable>
		source-validation <strict|loose|disable>
		syn-cookies <enable|disable>


Example:

	 filter
	     chain FORWARD {
	         policy DROP
	         rule 10 {
	             exec "-m state --state RELATED,ESTABLISHED -j ACCEPT"
	         }
	         rule 20 {
	             exec "-i [lan] -o [wan] -j ACCEPT"
	         }
	         rule 30 {
	             exec "-i [wan] -o [lan] -m policy --dir in --pol ipsec -j ACCEPT"
	         }
	         rule 40 {
	             exec "-i [wan] -o [lan] -j REJECT --reject-with icmp-port-unreachable"
	         }
	     }
	     chain INPUT {
	         policy ACCEPT
	         protected-update enable
	         rule 10 {
	             exec "-m state --state RELATED,ESTABLISHED -j ACCEPT"
	         }
	         rule 20 {
	             exec "-i lo -j ACCEPT"
	         }
	         rule 30 {
	             exec "-p tcp --syn -j syn_flood"
	         }
	         rule 40 {
	             exec "-i [lan] -j ACCEPT"
	         }
	         rule 50 {
	             exec "-i [wan] -p icmp --icmp-type echo-request -j ACCEPT"
	         }
	         rule 60 {
	             exec "-i [wan] -p icmp --icmp-type fragmentation-needed -j ACCEPT"
	         }
	         rule 70 {
	             exec "-i [wan] -m policy --dir in --pol ipsec -j ACCEPT"
	         }
	         rule 80 {
	             exec "-j REJECT --reject-with icmp-port-unreachable"
	         }
	     }
	     chain OUTPUT {
	         policy ACCEPT
	         rule 10 {
	             exec "-o [wan] -p esp -j ACCEPT"
	         }
	         rule 20 {
	             exec "-o [wan] -m mark --mark [vpn-mark] -j drop_if_no_ipsec"
	         }
	     }
	     chain drop_if_no_ipsec {
	         rule 10 {
	             exec "-m policy --dir out --pol ipsec -j RETURN"
	         }
	         rule 20 {
	             exec "-j DROP"
	         }
	     }
	     chain syn_flood {
	         rule 10 {
	             exec "-p tcp --syn -m limit --limit 25/sec --limit-burst 50 -j RETURN"
	         }
	         rule 20 {
	             exec "-j DROP"
	         }
	     }
	 }
	 ipset vpn-dst {
	     type hash:ip
	 }
	 ipset vpn-src {
	     type hash:ip
	 }
	 mangle {
	     chain OUTPUT {
	         rule 10 {
	             exec "-o [wan] -p udp --dport 53 -j MARK --set-mark [vpn-mark]"
	         }
	     }
	     chain POSTROUTING {
	         rule 10 {
	             exec "-o [wan] -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
	         }
	     }
	     chain PREROUTING {
	         rule 10 {
	             exec "-i [lan] -p udp --dport 5060 -j MARK --set-mark [vpn-mark]"
	         }
	         rule 20 {
	             exec "-m set --match-set vpn-dst dst -j MARK --set-mark [vpn-mark]"
	         }
	         rule 30 {
	             exec "-m set --match-set vpn-src src -j MARK --set-mark [vpn-mark]"
	         }
	     }
	 }
	 nat {
	     chain POSTROUTING {
	         rule 10 {
	             exec "-o [wan] -m mark --mark [vpn-mark] -j ACCEPT"
	         }
	         rule 20 {
	             exec "-o [wan] -j MASQUERADE"
	         }
	     }
	 }
	 variable lan {
	     value eth0
	 }
	 variable vpn-mark {
	     value 0x1
	 }
	 variable wan {
	     value pppoe0
	 } 
