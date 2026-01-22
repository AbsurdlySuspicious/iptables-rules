from iptables_rules import *

chain_in = chain(FILTER, INPUT, DROP)
chain_fwd = chain(FILTER, FORWARD, DROP)
chain(FILTER, OUTPUT, ACCEPT)

custom_in = chain(FILTER, "CUSTOM_INPUT").create_or_flush()
cf_wl = chain(FILTER, "CUSTOM_WHITELIST").create_or_flush()

r(custom_in, p(if_in="lo"), t=j(ACCEPT))
r(custom_in, p(proto=ICMP), t=j(ACCEPT))
r(custom_in, p(), m("conntrack", ctstate="RELATED,ESTABLISHED"), t=j(ACCEPT))
r(custom_in, p(), m(TCP, dport=22), t=j(ACCEPT))  # ssh
r(custom_in, p(), m(UDP, dport="60001:60030"), t=j(ACCEPT))  # mosh
r(custom_in, p(proto=TCP), m("multiport", dports=[80, 443]), t=j(cf_wl))
r(custom_in, p(proto=TCP), t=j("REJECT", reject_with="tcp-reset"))
Inject(chain_in, custom_in).inject()

whitelist(
    lambda c: r(c.chain, p(src=c.net), t=j(ACCEPT), ip=c.ipv),
    (cf_wl, WhitelistCF()),
)

all_tables().commit()

