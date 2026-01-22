from abc import ABCMeta, abstractmethod
from typing import Any, Callable, Self, Union, assert_never
from collections.abc import Iterable
import enum
from iptc.ip4tc import Table, Rule, Chain, Match, Target
from iptc.ip6tc import Table6, Rule6
from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
    ip_address as ip_address,
    ip_network as ip_network,
)


class InjectPos(int, enum.ReprEnum):
    First = -1
    Last = 1


class IP(int, enum.ReprEnum):
    v4 = 4
    v6 = 6

    @classmethod
    def iter_proto(cls, v: "IP | None"):
        if v is not None:
            return (v,)
        return (cls.v4, cls.v6)

    def create_rule(self, chain: "DeclarativeChain"):
        if self == IP.v4:
            return Rule(chain=chain.chain_v4)
        if self == IP.v6:
            return Rule6(chain=chain.chain_v6)
        assert_never(self)


class Proto(int, enum.ReprEnum):
    TCP = enum.auto()
    UDP = enum.auto()
    ICMP = enum.auto()

    def to_proto(self, ip_version: IP):
        if self == Proto.ICMP:
            if ip_version == IP.v4:
                proto = "icmp"
            elif ip_version == IP.v6:
                proto = "icmpv6"
            else:
                assert_never(ip_version)
        elif self == Proto.TCP:
            proto = "tcp"
        elif self == Proto.UDP:
            proto = "udp"
        else:
            assert_never(self)
        return proto


RuleAny = Rule | Rule6
IPAddressValues = str | IPv4Address | IPv6Address | IPv4Network | IPv6Network
ProtoValues = Proto | str
ParamValuesScalar = str | int | IPAddressValues
ParamValues = ParamValuesScalar | list[ParamValuesScalar]
ParamDict = dict[str, ParamValues]


@dataclass
class IPMap:
    v4: IPAddressValues | None = None
    v6: IPAddressValues | None = None
    invert: bool = False

    def _prepare_ip(self, ip: IPAddressValues):
        ip_str = str(ip)
        if self.invert:
            return f"!{ip_str}"
        else:
            return ip_str

    def get_addr(self, version: IP):
        if version == IP.v4:
            if self.v4 is None:
                raise Exception("IPv4 is missing from map")
            return self._prepare_ip(self.v4)
        if version == IP.v6:
            if self.v6 is None:
                raise Exception("IPv6 is missing from map")
            return self._prepare_ip(self.v6)
        assert_never(version)


@dataclass
class PendingMatch:
    matcher: str | Proto
    params: ParamDict
    proto_match: Proto | None = field(default=None, init=False)

    def __post_init__(self):
        if isinstance(self.matcher, Proto):
            self.proto_match = self.matcher

    @staticmethod
    def _prepare_value(v: Any):
        if isinstance(v, list):
            v = ",".join(str(e) for e in v)
        return str(v)

    def apply(self, rule: RuleAny, ip_version: IP):
        if isinstance(self.matcher, Proto):
            matcher = self.matcher.to_proto(ip_version)
        else:
            matcher = self.matcher
        i = Match(rule, matcher)
        for k, v in self.params.items():
            setattr(i, k, self._prepare_value(v))
        rule.add_match(i)
        return i


def inv(v: Any):
    return "!" + PendingMatch._prepare_value(v)


def match(matcher: str | Proto, **params: ParamValues):
    return PendingMatch(matcher, params)


@dataclass
class PendingTarget:
    name: str
    params: ParamDict
    goto: bool = field(kw_only=True, default=False)

    def apply(self, rule: RuleAny):
        i = Target(rule, self.name, goto=self.goto)
        for k, v in self.params.items():
            setattr(i, k, PendingMatch._prepare_value(v))
        rule.target = i
        return i


def chain_target(
    tgt: Union[str, "DeclarativeChain"], *, goto: bool, **params: ParamValues
):
    if isinstance(tgt, DeclarativeChain):
        name = tgt.chain_name
    else:
        name = tgt
    return PendingTarget(name, params, goto=goto)


def jump(tgt: Union[str, "DeclarativeChain"], **params: ParamValues):
    return chain_target(tgt, goto=False, **params)


def goto(tgt: Union[str, "DeclarativeChain"], **params: ParamValues):
    return chain_target(tgt, goto=True, **params)


@dataclass
class RuleParams:
    proto: ProtoValues | None = None
    src: IPAddressValues | IPMap | None = None
    dst: IPAddressValues | IPMap | None = None
    if_in: str | None = None
    if_out: str | None = None

    @staticmethod
    def _set_param(rule: RuleAny, prop: str, value: Any):
        if value is None:
            return
        setattr(rule, prop, str(value))

    @classmethod
    def _set_ip(
        cls,
        rule: RuleAny,
        prop: str,
        ip: IPAddressValues | IPMap | None,
        version: IP,
    ):
        if ip is None:
            return
        if isinstance(ip, IPMap):
            ip = ip.get_addr(version)
        return cls._set_param(rule, prop, ip)

    def apply(self, rule: RuleAny, ip_version: IP):
        if isinstance(self.proto, str):
            proto = self.proto
        elif self.proto is None:
            proto = None
        else:
            proto = self.proto.to_proto(ip_version)
        self._set_param(rule, "protocol", proto)
        self._set_param(rule, "in_interface", self.if_in)
        self._set_param(rule, "out_interface", self.if_out)
        self._set_ip(rule, "src", self.src, ip_version)
        self._set_ip(rule, "dst", self.dst, ip_version)


@dataclass
class PendingRule:
    chain: "DeclarativeChain"
    ip_version: IP | None
    params: RuleParams
    matchers: list[PendingMatch]
    target: PendingTarget

    def __post_init__(self):
        self.added_rules: list[RuleAny] = []

    def _inflate_rule(self, version: IP):
        rule = version.create_rule(self.chain)
        self.params.apply(rule, version)
        self.target.apply(rule)
        for m in self.matchers:
            if m.proto_match is not None:
                if self.params.proto is None:
                    self.params.proto = m.proto_match
                    self.params.apply(rule, version)
                elif self.params.proto != m.proto_match:
                    raise Exception(
                        "Mismatching protocols in matcher and route params", m, self
                    )
            m.apply(rule, version)
        self.added_rules.append(rule)
        return rule

    def add_to_chain(self, at_pos: int | None = None):
        self.added_rules.clear()
        for ip_version in IP.iter_proto(self.chain.get_ip_ver(self.ip_version)):
            rule = self._inflate_rule(ip_version)
            target_chain = self.chain.chain(ip_version)
            if at_pos is None:
                target_chain.append_rule(rule)
            else:
                target_chain.insert_rule(rule, at_pos)


def rule(
    chain: "DeclarativeChain",
    params: RuleParams,
    *matches: PendingMatch,
    t: PendingTarget,
    ip: IP | None = None,
    add: bool = True,
):
    rule = PendingRule(chain, ip, params, list(matches), t)
    if add:
        rule.add_to_chain()
    return rule


table_chains = {}
chain_instances = {}
table_instances = {}


def _call_attrs_wrapper(instances: Iterable[Any], item):
    def _wrapper(*args, **kwargs):
        for t in instances:
            getattr(t, item)(*args, **kwargs)

    _wrapper.__name__ = item
    _wrapper.__qualname__ = item
    return _wrapper


class TableProxy:
    fused_methods = ("commit", "flush", "refresh", "close")

    def __new__(cls, table_name: str) -> Self:
        try:
            return table_instances[table_name]
        except KeyError:
            return super().__new__(cls)

    def __init__(self, table_name: str) -> None:
        self.table_v4 = Table(table_name, autocommit=False)
        self.table_v6 = Table6(table_name, autocommit=False)
        table_instances[table_name] = self

    def table(self, version: IP):
        if version == IP.v4:
            return self.table_v4
        if version == IP.v6:
            return self.table_v6
        assert_never(version)

    def _call_all_wrapper(self, item):
        return _call_attrs_wrapper((self.table_v4, self.table_v6), item)

    def __getattr__(self, item):
        if item in self.fused_methods:
            for chain in chain_instances.values():
                chain._reset_state()
            return self._call_all_wrapper(item)
        raise AttributeError(name=item, obj=self)

    def strerrors(self) -> dict[str, str]:
        return dict(ipv4=self.table_v4.strerror(), ipv6=self.table_v6.strerror())


class AllTablesProxy:
    def __new__(cls) -> Self:
        if not hasattr(cls, "instance"):
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self) -> None:
        self._tables = table_instances

    def iter_tables(self) -> Iterable[TableProxy]:
        if isinstance(self._tables, dict):
            return self._tables.values()
        return iter(self._tables)

    def _call_all_wrapper(self, item):
        return _call_attrs_wrapper(self.iter_tables(), item)

    def __getattr__(self, item):
        if item in TableProxy.fused_methods:
            return self._call_all_wrapper(item)
        raise AttributeError(name=item, obj=self)


def table(table_name: str) -> TableProxy:
    return TableProxy(table_name)


def all_tables() -> AllTablesProxy:
    return AllTablesProxy()


@dataclass
class DeclarativeChain:
    table_name: str
    chain_name: str
    ip_version: IP | None = None

    def __post_init__(self):
        if (chain_set := table_chains.get(self.table_name)) is not None:
            if self.chain_name in chain_set:
                raise Exception(
                    f"Duplicate instance for chain {self.table_name}.{self.chain_name}"
                )
            chain_set.add(self.chain_name)
        else:
            table_chains[self.table_name] = {self.chain_name}
        chain_instances[self.table_name, self.chain_name] = self
        self.table = table(self.table_name)
        self.chain_v4 = Chain(self.table.table_v4, self.chain_name)
        self.chain_v6 = Chain(self.table.table_v6, self.chain_name)
        self._reset_state()

    def _reset_state(self):
        self.created = {}

    def chain(self, version: IP) -> Chain:
        if version == IP.v4:
            return self.chain_v4
        if version == IP.v6:
            return self.chain_v6
        assert_never(version)

    def all_chains(self) -> list[Chain]:
        return [self.chain(v) for v in IP.iter_proto(self.ip_version)]

    def get_ip_ver(self, override: IP | None = None):
        if self.ip_version is None:
            return override
        if override is not None and self.ip_version != override:
            raise Exception("Rule and chain mismatch", self, override)
        return self.ip_version

    def exists(self, version: IP) -> bool:
        if (is_created := self.created.get(version)) is None:
            chain_list = self.table.table(version).chains
            this_chain_id = id(self.chain(version))
            self.created[version] = is_created = any(
                id(c) == this_chain_id for c in chain_list
            )
        return is_created

    def _create_chain(self, v: IP):
        self.table.table(v).create_chain(self.chain(v))

    def create_or_flush(self, version: IP | None = None):
        for v in IP.iter_proto(self.get_ip_ver(version)):
            if self.exists(v):
                self.chain(v).flush()
            else:
                self._create_chain(v)
        return self

    def create_if_not_exists(self, version: IP | None = None):
        for v in IP.iter_proto(self.get_ip_ver(version)):
            if not self.exists(v):
                self._create_chain(v)
        return self

    def set_policy(self, policy: str, version: IP | None = None):
        for v in IP.iter_proto(self.get_ip_ver(version)):
            self.chain(v).set_policy(policy)
        return self

    def delete(
        self, version: IP | None = None, uninject_chains: list[Self] | None = None
    ):
        for u_chain in uninject_chains or ():
            Inject(u_chain, self).uninject()
        for v in IP.iter_proto(self.get_ip_ver(version)):
            if self.exists(v):
                chain_i = self.chain(v)
                chain_i.flush()
                chain_i.delete()
        return self

    def ensure_protocol(self, uninject_chains: list[Self] | None = None):
        if self.ip_version is None:
            return self
        for ip_v in IP.iter_proto(None):
            if ip_v == self.ip_version:
                continue
            for u_chain in uninject_chains or ():
                Inject(u_chain, self).uninject(ignore_version=True)
            self.chain(ip_v).delete()
        return self


def chain(
    table_name: str,
    chain_name: str,
    policy: str | None = None,
    ip: IP | None = None,
):
    try:
        chain = chain_instances[table_name, chain_name]
        if ip is not None and ip != chain.ip_version:
            raise Exception("IP version mismatch", chain.ip_version, ip)
    except KeyError:
        chain = DeclarativeChain(table_name, chain_name, ip)
    if policy is not None:
        chain.set_policy(policy, chain.ip_version)
    return chain


@dataclass
class Inject:
    target_chain: DeclarativeChain
    jump_chain: DeclarativeChain

    def __post_init__(self):
        if self.target_chain.table_name != self.jump_chain.table_name:
            raise Exception(
                "Target mismatch for target and jump chain",
                self.target_chain,
                self.jump_chain,
            )

    def uninject(self, *, ignore_version: bool = False):
        target_chain = self.target_chain
        jump_chain = self.jump_chain
        if ignore_version:
            ip_version = None
        else:
            ip_version = jump_chain.ip_version
        for ip_v in IP.iter_proto(ip_version):
            t = target_chain.chain(ip_v)
            for r in t.rules:
                if r.target.name == jump_chain.chain_name:
                    t.delete_rule(r)

    def inject(
        self,
        params: RuleParams | None = None,
        *matches: PendingMatch,
        ip: IP | None = None,
        place: InjectPos = InjectPos.Last,
    ):
        self.uninject()
        target_chain = self.target_chain
        jump_chain = self.jump_chain
        rule_i = rule(
            target_chain,
            params or p(),
            *matches,
            t=j(jump_chain.chain_name),
            ip=jump_chain.get_ip_ver(ip),
            add=False,
        )
        if place == InjectPos.First:
            rule_i.add_to_chain(at_pos=0)
        elif place == InjectPos.Last:
            rule_i.add_to_chain()
        else:
            assert_never(place)


m = match
j = jump
g = goto
r = rule
params = RuleParams
p = RuleParams


FILTER = Table.FILTER
MANGLE = Table.MANGLE
RAW = Table.RAW
NAT = Table.NAT
SECURITY = Table.SECURITY
ALL = Table.ALL

TCP = Proto.TCP
UDP = Proto.UDP
ICMP = Proto.ICMP

IPv4 = IP.v4
IPv6 = IP.v6

FIRST = InjectPos.First
LAST = InjectPos.Last

INPUT = "INPUT"
OUTPUT = "OUTPUT"
FORWARD = "FORWARD"

ACCEPT = "ACCEPT"
DROP = "DROP"
RETURN = "RETURN"


class Whitelist(metaclass=ABCMeta):
    @abstractmethod
    def get_ipv4(self) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def get_ipv6(self) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def get_header(self) -> str:
        raise NotImplementedError


class WhitelistCF(Whitelist):
    def _get_addrs(self, kind: str) -> list[str]:
        import requests

        resp = requests.get(f"https://www.cloudflare.com/ips-{kind}")
        return resp.text.splitlines()

    def get_ipv4(self) -> list[str]:
        return self._get_addrs("v4")

    def get_ipv6(self) -> list[str]:
        return self._get_addrs("v6")

    def get_header(self) -> str:
        return "cf_connecting_ip"


def _whitelist_nginx(whxs: list[Whitelist]) -> str:
    def _map_key(n: int):
        key = []
        for i in range(len(whxs)):
            key.append("1" if i == n else "0")
        return ":".join(key)

    def _geo(w: Whitelist):
        ips = [*w.get_ipv4(), *w.get_ipv6()]
        for ip in ips:
            yield f"set_real_ip_from {ip};"
        yield f"geo $realip_remote_addr $rip_use_{w.get_header()} {{"
        yield "  default 0;"
        for ip in ips:
            yield f"  {ip} 1;"
        yield "}"

    def _map():
        map_val = ":".join(f"$rip_use_{w.get_header()}" for w in whxs)
        yield f'map "{map_val}" $real_ip {{'

        for i, w in enumerate(whxs):
            yield f'  "{_map_key(i)}" $http_{w.get_header()};'

        yield from (
            "}",
            'more_set_input_headers "X-Nginx-IP: $real_ip";',
            "real_ip_header X-Nginx-IP;",
        )

    def _compose():
        for w in whxs:
            yield from _geo(w)
        yield from _map()

    return "\n".join(_compose())


@dataclass
class WhitelistRuleParams:
    net: str
    chain: DeclarativeChain
    ipv: IP


def whitelist(
    rule_cb: Callable[[WhitelistRuleParams], PendingRule],
    *whxs: tuple[DeclarativeChain, Whitelist],
    ngx_rip_file: str | None = "nginx_rip.conf",
):
    if ngx_rip_file is not None:
        rip = _whitelist_nginx(list(wt[1] for wt in whxs))
        with open(ngx_rip_file, "w") as f:
            f.write(rip)

    def _add_rules(ips: list[str], ipv: IP):
        for ip in ips:
            rule_cb(WhitelistRuleParams(ip, chain, ipv))

    for chain, w in whxs:
        _add_rules(w.get_ipv4(), IP.v4)
        _add_rules(w.get_ipv6(), IP.v6)
