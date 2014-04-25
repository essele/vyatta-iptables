vyatta-iptables
===============

Vyatta configuration templates and scripts to support low level access to
iptables and ipsets.

This module will effectively disable itself if any of the other mechanisms
are configured (firewall, port-forward or zone-policy.)

Basic variables are also supported which allows for expansion in iptables
rules. If a variable contains multiple items the rule will be duplicated for
each item. Multiple multi-variables can be used.

Configuration commands:

    service
        dns
            domain-match <name>
                domain <domain name>
                group <address group>

## domain

    match against this domain name. multiple can be defined for each set.
    see dnsmasq --ipset syntax for more information

## group

    populate this address group with the results

Example:

    service
        dns
            domain-match iplayer
                domain bbc.co.uk
                domain bbci.co.uk
                domain akamaihd.com
                group via-uk
 
## Technical details

This package just creates an additional config in /etc/dnsmasq.d
which takes advantage of the ipset capability within dnsmasq.

On reboot it is removed before config load and re-created if
related configuration exists.
