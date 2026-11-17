#!/usr/bin/env bash
# Black-box tests for scripts/check-public.sh and the git hooks, against throw-away repositories.
# Uses only a fixture deny-list (never the operator's). Offending strings are assembled at run time
# so this file itself carries no address, e-mail, host name or home path.
#   usage: [ONLY=ID] scripts/test-check-public.sh [-v]     exit 1 when any non-note case fails; ONLY runs one case and shows its output
set -uo pipefail
export TZ=UTC                                            # the gate refuses other commit time zones
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GATE=$ROOT/scripts/check-public.sh
T=$(mktemp -d); trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
VERBOSE=${1:-}
Q() { printf '%s' "${1//\~/:}"; }
J() { local IFS=$1; shift; printf '%s' "$*"; }          # join with a separator
PUB=$(J . 8 8 4 4); PUB2=$(J . 1 1 1 1); VER=$(J . 17 6 1 166)
DW=zz""deny                                              # the fixture deny-list word
W2=word""two
AT=@
mail() { printf '%s%s%s.%s' "$1" "$AT" "$2" "$3"; }      # mail user dom tld
hp() { printf '/%s/%s/x' "$1" "$2"; }                    # hp home alice
host() { J . "$@"; }
GHN=$(host users noreply github com)                    # GitHub per-user noreply domain
export SUPAPACE_DENYLIST=$T/deny
printf "# fixture\n%s\n\n  # indented comment\n%s\n" "$DW" "$W2" >"$SUPAPACE_DENYLIST"

N=0; PASSN=0; FAILN=0; NOTEN=0; FAILS=()
gate() { "$GATE" "$@" >.gate.out 2>&1; }
f() { mkdir -p "$(dirname "$1")"; printf '%b' "$2" >"$1"; git add -- "$1"; }   # stage file
allowf() { mkdir -p scripts; printf '%s\n' "$@" >scripts/public-allow.txt; git add scripts/public-allow.txt; }   # staged allow file
fresh() { # new repo, cwd inside; no hooks
	D=$(mktemp -d -p "$T"); cd "$D" || exit 99
	git init -q -b main; git config user.name tester; git config user.email "1+tester$AT$GHN"
	git config commit.gpgsign false
}
hooked() { fresh; mkdir -p scripts .githooks; printf '#!/bin/sh\nexec "%s" "$@"\n' "$GATE" >scripts/check-public.sh; chmod +x scripts/check-public.sh; cp "$ROOT"/.githooks/* .githooks/; git config core.hooksPath .githooks; }
# chk ID "name" block|pass|note body   (body's exit status = gate status)
chk() { [[ -n ${ONLY:-} && $1 != $ONLY ]] && return 0
	local id=$1 name=$2 exp=$3 body=$4 rc act res
	N=$((N+1))
	rc=$( (fresh; $body; echo $? >"$T/rc"; [[ -f .gate.out ]] && cp .gate.out "$T/out" || : >"$T/out"); cat "$T/rc" ); [[ -n ${ONLY:-} ]] && cat "$T/out"
	[[ $rc == 0 ]] && act=pass || act=block
	if [[ $exp == note ]]; then res=NOTE; NOTEN=$((NOTEN+1))
	elif [[ $exp == $act ]]; then res=PASS; PASSN=$((PASSN+1))
	else res=FAIL; FAILN=$((FAILN+1)); FAILS+=("$id"); fi
	printf '%-5s %-4s %-62s exp=%-5s act=%-5s\n' "$res" "$id" "$name" "$exp" "$act"
}
leak() { # no offending text in the report
	grep -qF -- "$1" "$T/out" && return 1 || return 0
}

# ---- deny-list ----
b_dl_content() { f a.txt "hello $DW world\n"; gate --staged; }
chk D01 "deny-list hit in file content" block b_dl_content
b_dl_leak() { f a.txt "hello $DW world\n"; gate --staged; leak "$DW"; }
chk D01b "report never prints offending text" pass b_dl_leak
b_dl_name() { f "$DW.txt" "clean\n"; gate --staged; }
chk D02 "deny-list hit in file name" block b_dl_name
b_dl_mixed() { f a.txt "hello $(printf Zz)DeNy world\n"; gate --staged; }
chk D03 "deny-list hit, mixed case" block b_dl_mixed
b_dl_split() { f a.txt "zz\ndeny\n"; gate --staged; }
chk D04 "hit split across two lines" note b_dl_split
b_dl_second() { f a.txt "x ${W2} y\n"; gate --staged; }
chk D05 "second deny-list line applies" block b_dl_second
b_dl_comment() { f a.txt "comment fixture\n"; gate --staged; }
chk D06 "clean content passes" pass b_dl_comment
b_dl_anchor() { printf '^start%s\n' "$DW" >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "start${DW} here\n"; gate --staged; }
chk D07 "anchored ^pattern matches start of content line" block b_dl_anchor
b_dl_missing() { SUPAPACE_DENYLIST=$PWD/none; export SUPAPACE_DENYLIST; f a.txt "ok\n"; gate --staged; }
chk D08 "missing deny-list (--staged)" block b_dl_missing
b_dl_missing_m() { SUPAPACE_DENYLIST=$PWD/none; export SUPAPACE_DENYLIST; echo "msg" >m; gate --message m; }
chk D09 "missing deny-list (--message)" block b_dl_missing_m
b_dl_missing_t() { SUPAPACE_DENYLIST=$PWD/none; export SUPAPACE_DENYLIST; f a.txt "ok\n"; gate --tree; }
chk D10 "missing deny-list (--tree)" block b_dl_missing_t
b_dl_empty() { : >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "ok $DW\n"; gate --staged; }
chk D11 "empty deny-list file, content with fixture word" block b_dl_empty
b_dl_comments_only() { printf '# only\n\n' >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "ok\n"; gate --staged; }
chk D12 "comments-only deny-list, clean content" block b_dl_comments_only
b_dl_badre() { printf '[unclosed\n%s\n' "$DW" >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "ok $DW\n"; gate --staged; }
chk D13 "invalid regex line + valid line + hit (fail closed)" block b_dl_badre
b_dl_badre_clean() { printf '[unclosed\n' >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "ok\n"; gate --staged; }
chk D14 "invalid regex only, clean content (must not pass silently)" block b_dl_badre_clean
b_dl_crlf() { printf '%s\r\n' "$DW" >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "ok $DW\n"; gate --staged; }
chk D15 "deny-list file with CRLF line endings" block b_dl_crlf
b_dl_unreadable() { [[ $(id -u) == 0 ]] && return 1; printf '%s\n' "$DW" >dl; chmod 000 dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "ok $DW\n"; gate --staged; }
chk D16 "unreadable deny-list (mode 000)" block b_dl_unreadable
b_dl_dir() { mkdir dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "ok\n"; gate --staged; }
chk D17 "deny-list path is a directory" block b_dl_dir
b_dl_nonascii_name() { printf '%s\n' 'ünique' >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f "ünique.txt" "ok\n"; gate --staged; }
chk D18 "non-ASCII deny word in file name" block b_dl_nonascii_name
b_dl_nonascii_content() { printf '%s\n' 'ünique' >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "x ÜNIQUE y\n"; gate --staged; }
chk D19 "non-ASCII deny word, other case, in content" block b_dl_nonascii_content
b_dl_name_space() { f "a b $DW c.txt" "ok\n"; gate --staged; }
chk D20 "deny hit in file name with spaces" block b_dl_name_space
b_dl_name_nl() { f $'a\n'"$DW"'.txt' "ok\n"; gate --staged; }
chk D21 "deny hit in file name with newline" block b_dl_name_nl
b_dl_name_dir() { f "$DW/inner/file.txt" "ok\n"; gate --staged; }
chk D22 "deny hit in directory component" block b_dl_name_dir

# ---- IPv4 ----
ip4() { f a.txt "$1\n"; gate --staged; }
b1() { ip4 "server $PUB here"; };            chk I01 "public IPv4 plain" block b1
b2() { ip4 "addr: $PUB"; };                  chk I02 "public IPv4 after ': '" block b2
b3() { ip4 "ip=$PUB"; };                     chk I03 "public IPv4 after '='" block b3
b4() { ip4 "http://$PUB:8080/x"; };          chk I04 "public IPv4 in URL" block b4
b5() { ip4 "{\"ip\":\"$PUB\"}"; };           chk I05 "public IPv4 in JSON" block b5
b6() { ip4 "host:$PUB"; };                   chk I06 "public IPv4 right after ':' (host:ip)" block b6
b7() { ip4 "$(Q '~~ffff~')$PUB"; };                 chk I07 "public IPv4 as IPv4-mapped IPv6" block b7
b8() { ip4 "x.$PUB"; };                      chk I08 "public IPv4 after '.'" note b8
b9() { ip4 "see $PUB."; };                   chk I09 "public IPv4 before sentence dot" block b9
b10() { ip4 "$(J . 192 168 1 1)"; };         chk I10 "RFC1918 192 dot 168/16" block b10
b11() { ip4 "$(J . 172 16 0 1)"; };          chk I11 "RFC1918 172 dot 16/12" block b11
b12() { ip4 "$(J . 10 0 0 1)"; };            chk I12 "10 dot 0 dot 0 dot 1 (outside 10 dot 212 dot 0 dot 0/14)" block b12
b13() { ip4 "$(J . 10 211 255 255) $(J . 10 216 0 0)"; }; chk I13 "10 dot 211 dot 255 dot 255 and 10 dot 216 dot 0 dot 0 (just outside /14)" block b13
b14() { ip4 "$(J . 10 212 0 0) $(J . 10 215 255 255) $(J . 10 213 255 195)"; }; chk I14 "10 dot 212 dot 0 dot 0 .. 10 dot 215 dot 255 dot 255 allowed" pass b14
b15() { ip4 "$(J . 127 0 0 1) $(J . 127 255 255 254)"; }; chk I15 "loopback 127/8" pass b15
b16() { ip4 "$(J . 169 254 169 254)"; };    chk I16 "169 dot 254 dot 169 dot 254 allowed" pass b16
b17() { ip4 "$(J . 169 254 1 1)"; };         chk I17 "link-local 169 dot 254 dot 1 dot 1 (other than metadata)" block b17
b18() { ip4 "$(J . 0 0 0 0)"; };             chk I18 "0 dot 0 dot 0 dot 0" pass b18
b19() { ip4 "$(J . 192 0 2 1) $(J . 198 51 100 9) $(J . 203 0 113 250)"; }; chk I19 "RFC 5737 documentation ranges" pass b19
b20() { ip4 "$(J . 203 0 114 1)"; };         chk I20 "203 dot 0 dot 114 dot 1 (next to documentation range)" block b20
b21() { ip4 "image supabase/postgres:17.6.1.166"; }; chk I21 "version in image tag 17 dot 6 dot 1 dot 166" pass b21
b22() { allowf "$VER # fixture"; ip4 "version $VER pinned"; };  chk I22 "bare version 17 dot 6 dot 1 dot 166 in prose" pass b22
b22b() { ip4 "version $VER pinned"; };          chk I22b "bare version without an allow-file entry" block b22b
b23() { ip4 "v$VER and postgres-$VER"; }; chk I23 "v-prefixed / hyphenated version" pass b23
b24() { ip4 "mask 0.0.0.63 == 0.0.0.2"; };   chk I24 "mask 0 dot 0 dot 0 dot 63" pass b24
b25() { ip4 "$(J . 0 1 2 3)"; };             chk I25 "0 dot 1 dot 2 dot 3 (inside 0 dot 0 dot 0 dot 0/8)" note b25
b26() { ip4 "$(J . 256 1 1 1) $(J . 999 999 999 999)"; }; chk I26 "out-of-range octets are not addresses" pass b26
b27() { ip4 "8.8.8.8.8"; };                  chk I27 "five-part number" note b27
b28() { ip4 "a $PUB, b $PUB2"; };            chk I28 "two public IPs on one line" block b28
b29() { ip4 "$(J . 010 8 8 8)"; };           chk I29 "leading-zero octets 010 dot 8 dot 8 dot 8" block b29
b30() { printf 'x %s\r\n' "$PUB" >a.txt; git add a.txt; gate --staged; }; chk I30 "public IPv4 in CRLF line" block b30
b31() { ip4 "$(J . 100 64 0 1)"; };          chk I31 "CGNAT 100 dot 64 dot 0 dot 1" block b31
b32() { ip4 "$(J . 198 18 0 1)"; };          chk I32 "benchmark range 198 dot 18 dot 0 dot 1" block b32
b33() { ip4 "$(J . 255 255 255 255)"; };     chk I33 "broadcast 255 dot 255 dot 255 dot 255" pass b33
b34() { ip4 "$(J . 224 0 0 1)"; };           chk I34 "multicast 224 dot 0 dot 0 dot 1" block b34
b35() { ip4 "mask $(J . 255 255 255 0)"; };  chk I35 "netmask 255 dot 255 dot 255 dot 0" pass b35
b36() { ip4 "$PUB/24"; };                    chk I36 "public CIDR" block b36
b37() { ip4 "ip${PUB}"; };                   chk I37 "public IPv4 glued to letters" note b37

# ---- IPv6 ----
b60() { ip4 "$(Q 'ip 2606~4700~~1111')"; };         chk V01 "global IPv6 compressed" block b60
b61() { ip4 "$(Q '2606~4700~4700~0~0~0~0~1111')"; }; chk V02 "global IPv6 full eight groups" block b61
b62() { ip4 "$(Q 'at ~~1 and fe80~~1 and 0~~ and ~~')"; }; chk V03 "loopback, link-local, zero-prefixed unspecified, unspecified" pass b62
b63() { ip4 "$(Q 'fd00~ec2~~254 and 2001~db8~~1')"; }; chk V04 "metadata ULA and documentation range" pass b63
b64() { ip4 "$(Q 'fc00~~1')"; };                    chk V05 "ULA fc00" block b64
b65() { ip4 "$(Q 'fec0~~1')"; };                    chk V06 "site-local fec0" block b65
b66() { ip4 "$(Q 'febf~~1 and fe90~~2')"; };        chk V07 "link-local upper edge febf" pass b66
b67() { ip4 "$(Q '2606~4700~~1111%eth0')"; };       chk V08 "global with zone id" block b67
b68() { ip4 "$(Q '[2606~4700~~1111]~443')"; };      chk V09 "global in URL brackets" block b68
b69() { f a.txt "$(Q '2606~4700~~1111')\n"; gate --staged; }; chk V10 "global at line start/end" block b69
b70() { ip4 "$(Q '2001~DB8~~1')"; };                chk V11 "RFC 3849 upper-case" pass b70
b71() { ip4 "$(Q '12~30~45 and aa~bb~cc~dd~ee~ff')"; }; chk V12 "time and MAC not IPv6" pass b71
b72() { ip4 "$(Q '~~ffff~0~0 and 64~ff9b~~')$PUB"; }; chk V13 "NAT64 with embedded public v4" block b72
b73() { ip4 "$(Q '~~2')"; };                        chk V14 "colon-colon-2 (not loopback)" block b73
b74() { ip4 "$(Q '0~~1')"; };                       chk V15 "zero-colon loopback long form" note b74
b75() { ip4 "$(Q 'FE80~~1')"; };                    chk V16 "link-local upper-case" pass b75
b76() { ip4 "$(Q 'icmpv6 daddr { ff02~~1, ff02~~1~ff00~0/104 }')"; }; chk V17 "multicast (neighbour discovery rules)" pass b76

# ---- e-mail ----
b80() { ip4 "contact $(mail alice example com)"; }; chk E01 "e-mail in file" block b80
b81() { ip4 "$(mail a b test)"; };           chk E02 "e-mail on .test domain" block b81
b82() { ip4 "$(mail first.last+tag x co uk)"; }; chk E03 "e-mail with plus and subdomain" block b82
b83() { ip4 "git$AT""host.test:repo.git"; }; chk E04 "scp-style scp-style address" note b83
b84() { ip4 "$(mail noreply anthropic com)"; }; chk E05 "noreply address in a file (not a message trailer)" block b84
msg() { printf '%b' "$1" >m; gate --message m; }
m1() { msg "feat: x\n\nCo-Authored-By: Claude Fable 5.2 <$(mail noreply anthropic com)>\n"; }
chk E10 "message: Claude Co-Authored-By trailer" pass m1
m2() { msg "feat: x\n\nCo-authored-by: Claude Fable 5.2 <$(mail noreply anthropic com)>\n"; }
chk E11 "message: lower-case 'Co-authored-by' trailer" pass m2
m3() { msg "feat: x\n\nCo-Authored-By: Some One <12345+someone$AT$GHN>\n"; }
chk E12 "message: GitHub noreply trailer" pass m3
m3b() { msg "feat: x\n\nSigned-off-by: Some One <12345+someone$AT$GHN>\n"; }
chk E12b "message: Signed-off-by GitHub noreply" pass m3b
m3c() { msg "feat: x\n\nCo-Authored-By: Some One <someone$AT$GHN>\n"; }
chk E12c "message: Co-Authored-By GitHub noreply, no digits" pass m3c
m4() { msg "feat: x\n\nCo-Authored-By: Real <$(mail real example com)>\n"; }
chk E13 "message: Co-Authored-By with a real-looking address" block m4
m5() { msg "feat: x\n\ncontact $(mail alice example com)\n"; }
chk E14 "message: e-mail in body" block m5
m6() { msg "feat: x\n\nCo-Authored-By: Claude <$(mail noreply anthropic com)>\r\n"; }
chk E15 "message: trailer with CRLF" note m6
m7() { msg "feat: x\n\nCo-Authored-By: Bad $DW <$(mail noreply anthropic com)>\n"; }
chk E16 "message: deny word inside the Co-Authored-By trailer" block m7
m8() { msg "feat: x\n\nCo-Authored-By: Bad <$(mail noreply evil org)>\n"; }
chk E17 "message: noreply@<other domain> trailer" block m8
m9() { msg "feat: x\n\nCo-Authored-By: $PUB <$(mail noreply anthropic com)>\n"; }
chk E18 "message: public IPv4 inside trailer name" block m9
m10() { msg "feat: x\n\n# $PUB\n"; }
chk E19 "message: public IPv4 on a '#' line (git -m keeps it)" block m10
m11() { msg "feat: $DW\n"; }
chk E20 "message: deny word in subject" block m11
m12() { msg "feat: x\n\nsee $(hp home alice)\n"; }
chk E21 "message: home path" block m12
m13() { msg ""; }
chk E22 "message: empty file" pass m13
m14() { printf 'feat: x %s' "$DW" >m; gate --message m; }
chk E23 "message: no trailing newline" block m14
m15() { msg "feat: zz\ndeny\n"; }
chk E24 "message: deny word split across lines" note m15
m16() { msg "feat: x\n\n$(mail a b com)\n"; }
chk E25 "message: bare e-mail line" block m16
m17() { msg "$(printf 'x%.0s' $(seq 1 200000)) $DW\n"; }
chk E26 "message: very long line with hit" block m17

# ---- paths ----
p1() { ip4 "cd $(hp home alice)"; };         chk H01 "home dir <name>/ path" block p1
p2() { ip4 "cd $(hp Users bob)"; };          chk H02 "Users dir <name>/ path" block p2
p3() { ip4 "~/projects and /homes/x and /var/lib"; }; chk H03 "tilde path, /homes, /var/lib" pass p3
p4() { ip4 "C:\\\\Users\\\\carol\\\\x"; };    chk H04 "Windows C:\\Users\\<name>" block p4
p5() { ip4 "/var$(hp home dave)"; };         chk H05 "/varhome dir <name> (contains home dir )" block p5
p6() { f "sub$(hp home alice)" "ok\n"; gate --staged; }; chk H06 "home path as a file name" block p6
NR=$(printf '/%s/%s' home nonroot)
p7() { allowf "$NR # fixture"; ip4 "ENV HOME=$NR"; f b.txt "WORKDIR $NR/app\n"; gate --staged; }; chk H07 "home path listed exactly in the allow file" pass p7
p8() { allowf "$NR # fixture"; ip4 "ENV HOME=${NR}2 and $(hp home alice)"; }; chk H08 "home path not listed exactly in the allow file" block p8

# ---- hosts ----
h1() { ip4 "see $(host api corp com)"; };    chk N01 "host name .com" block h1
h2() { ip4 "$(host a sp test) $(host b example) $(host c invalid)"; }; chk N02 ".test .example .invalid" pass h2
h3() { allowf "$(host github com) # fixture" "$(host golang org) # fixture"; ip4 "$(host github com)/x $(host golang org)/y"; }; chk N03 "allow-file tokens, matched whole" pass h3
h3b() { allowf "$(host github com) # fixture"; ip4 "$(host x github com)"; }; chk N03b "subdomain of an allow-file token" block h3b
h4() { ip4 "$(host evilgithub com)"; };      chk N04 "look-alike of allowed host (look-alike)" block h4
h5() { ip4 "$(host github com evil com)"; }; chk N05 "allowed host as a label of another (suffix trick)" block h5
h6() { ip4 "$(host Corp Example com)"; };    chk N06 "mixed-case host name" block h6
h7() { ip4 "$(host corp EXAMPLE COM)"; };    chk N07 "upper-case host name" block h7
h8() { ip4 "$(host my_host evil com)"; };    chk N08 "host with underscore label" block h8
h9() { ip4 "$(host host evil fr)"; };        chk N09 "host in a TLD outside the script's list (.fr)" block h9
h10() { ip4 "https://$(host api corp io)/v1"; }; chk N10 "host in URL .io" block h10
h11() { ip4 "$(host cfg local) $(host s info) x.app x.dev x.me x.to t.at o.no"; }; chk N11 "selectors whose field is a TLD (two labels, weak TLD)" pass h11
h12() { ip4 "$(host a b c d e corp com)"; }; chk N12 "deep host name" block h12
h13() { ip4 "xn--$(host abc corp com)"; };  chk N13 "host with xn-- prefix glued" block h13
h14() { ip4 "$(host corp com):8080"; };      chk N14 "host with port" block h14
h16() { ip4 "$(host mail corp fr)"; };       chk N16 "three-label host under a weak TLD" block h16
h17() { ip4 "$(host db corp local)"; };      chk N17 "three-label host under a private-use TLD" block h17
h18() { ip4 "https://$(host Corp Com)/x"; }; chk N18 "title-case host name after ://" block h18
h19() { ip4 "$(host mail Mycorp Com)"; };    chk N19 "title-case host name with three labels" block h19

# ---- binary / CRLF / names / git states ----
g1() { printf 'x\0%s\0' "$DW" >bin.dat; git add bin.dat; gate --staged; }
chk G01 "binary file containing deny word" block g1
g2() { printf 'x\0%s\0' "$(hp home alice)" >bin.dat; git add bin.dat; gate --staged; }
chk G02 "binary file containing a home path" block g2
g3() { printf 'x\0' >"$DW.bin"; git add -- "$DW.bin"; gate --staged; }
chk G03 "binary file with deny word in name" block g3
g4() { printf 'a %s b\r\nline2\r\n' "$DW" >a.txt; git add a.txt; gate --staged; }
chk G04 "CRLF file with deny word" block g4
g5() { printf 'a %s\r\n' "$DW" >a.txt; git add a.txt; printf '%s$\n' "$DW" >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; gate --staged; }
chk G05 "CRLF file, deny pattern anchored with \$" block g5
g6() { f "has space.txt" "$PUB\n"; gate --staged; }
chk G06 "file name with spaces, content public IP" block g6
g7() { f $'new\nline.txt' "$PUB\n"; gate --staged; }
chk G07 "file name with newline, content public IP" block g7
g8() { f "tab	name.txt" "ok\n"; gate --staged; }
chk G08 "file name with tab, clean" pass g8
g9() { f a.txt "ok\n"; git -c user.name=x commit -qm init --no-verify; git rm -q a.txt; gate --staged; }
chk G09 "staged deletion of a file" pass g9
g10() { f "a.txt" "$PUB\n"; git commit -qm x --no-verify; git rm -q a.txt; gate --staged; }
chk G10 "staged deletion of a file that had a public IP" pass g10
g11() { f a.txt "line one\nline two\nline three\n"; git commit -qm x --no-verify; git mv a.txt "$DW.txt"; gate --staged; }
chk G11 "pure rename to a deny-listed name" block g11
g12() { f a.txt "one\ntwo\nthree\nfour\nfive\n"; git commit -qm x --no-verify; printf 'one\ntwo\nthree\nfour\nfive %s\n' "$PUB" >a.txt; git add a.txt; gate --staged; }
chk G12 "modified file, added line with public IP at EOF" block g12
g13() { f a.txt "one\ntwo\n"; git commit -qm x --no-verify; printf 'one\n++ %s\ntwo\n' "$PUB" >a.txt; git add a.txt; gate --staged; }
chk G13 "added line starting with '++ ' (looks like a diff header)" block g13
g14() { f a.txt "x\n"; gate --staged; }
chk G14 "very first commit state (no HEAD), clean" pass g14
g15() { f a.txt "$PUB\n"; gate --staged; }
chk G15 "very first commit state (no HEAD), public IP" block g15
g16() { gate --staged; }
chk G16 "nothing staged" pass g16
g17() { f a.txt "x\n"; git commit -qm x --no-verify; f b.txt "$PUB\n"; mkdir sub; cd sub; gate --tree; }
chk G17 "--tree run from a subdirectory (bad file at root)" block g17
g18() { f a.txt "$PUB\n"; gate --tree; }
chk G18 "--tree finds staged-not-committed bad content" block g18
g19() { f a.txt "$PUB\n"; (cd /; "$GATE" --tree >/dev/null 2>&1); }
chk G19 "--tree outside any git repository" block g19
g20() { f a.txt "ok\n"; gate --staged x; }
chk G20 "usage error: extra argument" block g20
g21() { gate; }
chk G21 "usage error: no argument" block g21
g22() { gate --message /nonexistent; }
chk G22 "--message with a missing file" block g22
g23() { f a.txt "x\n"; printf '%s %s %s\n' "$PUB" "$DW" "$(hp home a)" >a.txt; git add a.txt; gate --tree; }
chk G23 "--tree catches ip, deny word, home path in one file" block g23
g24() { f a.txt "$PUB\n"; git commit -qm x --no-verify; printf '%s\n' "$PUB" >>a.txt; gate --tree; }
chk G24 "--tree: tracked committed file with public IP" block g24
g25() { f "$DW.txt" "x\n"; git commit -qm x --no-verify; gate --tree; }
chk G25 "--tree: tracked file with deny word in name" block g25
g26() { printf 'x\0%s\0' "$DW" >bin.dat; git add bin.dat; gate --tree; }
chk G26 "--tree: binary file containing deny word" block g26
g27() { f "$(printf 'ünique')-$DW.txt" "x\n"; gate --staged; }
chk G27 "non-ASCII file name also holding ASCII deny word" block g27

# ---- hooks end to end ----
c_try() { # commit currently staged tree with message $1; 0 = commit created
	git commit -q -m "$1" >.gate.out 2>&1; return $?; }
k1() { hooked; f a.txt "$(hp home alice)\n"; c_try "feat: x"; }
chk K01 "hook refuses a commit containing a home path" block k1
k2() { hooked; f a.txt "ok\n"; c_try "feat: x"; }
chk K02 "hook accepts a clean commit (very first commit)" pass k2
k3() { hooked; f a.txt "ok\n"; c_try "feat: $DW"; }
chk K03 "commit-msg hook refuses deny word in subject" block k3
k4() { hooked; f a.txt "ok\n"; git commit -q -m "feat: x" -m "Co-Authored-By: Claude Fable 5.2 <$(mail noreply anthropic com)>" >.gate.out 2>&1; }
chk K04 "commit with the Claude trailer via -m -m" pass k4
k5() { hooked; f a.txt "ok\n"; c_try "feat: x"; f b.txt "ok2\n"; git commit -q --amend -m "feat: $DW" >.gate.out 2>&1; }
chk K05 "amend with deny word in new message" block k5
k6() { hooked; f a.txt "ok\n"; c_try "feat: x"; f b.txt "$PUB\n"; git commit -q --amend --no-edit >.gate.out 2>&1; }
chk K06 "amend --no-edit adding a public IP" block k6
k7() { hooked; f a.txt "ok\n"; c_try "feat: x"; git commit -q --amend --no-edit >.gate.out 2>&1; }
chk K07 "amend --no-edit of a clean commit (no staged changes)" pass k7
k8() { hooked; f a.txt "ok\n"; c_try "feat: x"; printf '%s\n' "$PUB" >>a.txt; git commit -q -a -m "feat: y" >.gate.out 2>&1; }
chk K08 "commit -a with an unstaged public IP in a tracked file" block k8
k9() { hooked; f a.txt "ok\n"; f c.txt "ok\n"; c_try "feat: x"; printf '%s\n' "$PUB" >>a.txt; git commit -q -m "feat: y" -- a.txt >.gate.out 2>&1; }
chk K09 "commit -- <path> (--only) with public IP" block k9
k10() { hooked; f a.txt "ok\n"; c_try "feat: x"; git checkout -q -b side; f b.txt "$PUB\n"; git commit -q -m "feat: s" --no-verify; git checkout -q main; f d.txt "ok\n"; c_try "feat: m"; git merge --no-ff -m "Merge side" side >.gate.out 2>&1; }
chk K10 "clean merge pulling in unchecked content (pre-merge-commit hook)" block k10
k11() { hooked; f a.txt "one\n"; c_try "feat: x"; git checkout -q -b side; printf 'side\n' >a.txt; git add a.txt; git commit -q -m s --no-verify; git checkout -q main; printf 'main\n' >a.txt; git add a.txt; git commit -q -m m --no-verify
	git merge side >/dev/null 2>&1; printf '%s\n' "$PUB" >a.txt; git add a.txt; git commit -q -m "Merge side" >.gate.out 2>&1; }
chk K11 "conflicted merge resolved with a public IP" block k11
k12() { hooked; f a.txt "ok\n"; c_try "feat: x"; git checkout -q -b side; f b.txt "ok\n"; git commit -q -m s; git checkout -q main; f d.txt "ok\n"; c_try "feat: m"; git merge --no-ff -m "Merge $DW" side >.gate.out 2>&1; }
chk K12 "merge commit message with deny word" block k12
k13() { hooked; f a.txt "ok\n"; git commit -q -m "feat: x" -m "# $PUB" >.gate.out 2>&1; }
chk K13 "git commit -m with a '#' body line holding a public IP" block k13
k14() { hooked; f a.txt "ok\n"; printf 'feat: x\n\nbody %s\n' "$DW" >msg.txt; git commit -q -F msg.txt >.gate.out 2>&1; }
chk K14 "commit -F file with deny word in body" block k14
k15() { hooked; f a.txt "ok\n"; git commit -q -m "fix: x" -m "Co-Authored-By: Bad $DW <$(mail noreply anthropic com)>" >.gate.out 2>&1; }
chk K15 "commit with deny word inside Co-Authored-By trailer" block k15
k16() { hooked; f a.txt "ok\n"; git -c core.commentChar=';' commit -q -m "fix: x" -m "; $PUB" >.gate.out 2>&1; }
chk K16 "custom comment char: line starting ';' holds a public IP" block k16
k17() { hooked; f a.txt "ok\n"; c_try "feat: x"; git tag -a v1 -m "release $DW" >.gate.out 2>&1; }
chk K17 "annotated tag message with deny word (no hook exists)" note k17

# ---- messages, exemptions, type changes, allow file, UTF-16, deny-list load ----
SCIS='# ------------------------ >8 ------------------------'
x1() { msg "feat: x\n\n$SCIS\n$DW\n"; }
chk E27 "message: text after a scissors line" block x1
x2() { msg "feat: x\n\nCo-Authored-By: X <123+$DW$AT$GHN>\n"; }
chk E28 "message: deny word as a GitHub noreply login" block x2
x3() { msg "feat: x\n\nCo-Authored-By: X <$DW-dev$AT$GHN>\n"; }
chk E29 "message: deny word inside a GitHub noreply address" block x3
x4() { f a.txt "ok\n"; git commit -qm x --no-verify; rm a.txt; ln -s "$(hp home alice)" a.txt; git add a.txt; gate --staged; }
chk G28 "type change: file to symlink with a home path" block x4
x5() { ln -s target a.txt; git add a.txt; git commit -qm x --no-verify; rm a.txt; printf '%s\n' "$DW" >a.txt; git add a.txt; gate --staged; }
chk G29 "type change: symlink to file with a deny word" block x5
x6() { allowf "$(host golang org) # fixture"; printf '%s # x\n' "$(host corp com)" >>scripts/public-allow.txt; f a.txt "$(host corp com)\n"; gate --staged; }
chk N15 "allow entry only in the work tree is ignored" block x6
u16() { printf '\xff\xfe'; local s=$1 i; for ((i = 0; i < ${#s}; i++)); do printf '%s\0' "${s:i:1}"; done; }
x7() { u16 "x $DW y" >w.txt; git add w.txt; gate --staged; }
chk G30 "UTF-16LE file with a deny word (--staged)" block x7
x8() { u16 "x $DW y" >w.txt; git add w.txt; gate --tree; }
chk G31 "UTF-16LE file with a deny word (--tree)" block x8
x9() { printf '\xef\xbb\xbf%s\n' "$DW" >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "ok $DW\n"; gate --staged; }
chk D23 "deny-list with a UTF-8 BOM keeps its first pattern" block x9
x10() { printf '%s\n^$\n' "$DW" >dl; SUPAPACE_DENYLIST=$PWD/dl; export SUPAPACE_DENYLIST; f a.txt "ok\n"; gate --staged; }
chk D24 "deny-list pattern that matches the empty string" block x10

# ---- --range ----
y1() { f a.txt "ok\n"; git commit -qm a --no-verify; f b.txt "$PUB\n"; git commit -qm b --no-verify; git rm -q b.txt; git commit -qm c --no-verify; gate --range HEAD; }
chk R02 "--range: leak in an old commit, removed later" block y1
y2() { git commit -q --allow-empty --no-verify -m "feat: $DW"; gate --range HEAD; }
chk R03 "--range: deny word in a message" block y2
y3() { git -c user.name="$DW" commit -q --allow-empty --no-verify -m "feat: x"; gate --range HEAD; }
chk R04 "--range: deny word in the author name" block y3
y4() { git -c user.email="a$AT$(host corp com)" commit -q --allow-empty --no-verify -m "feat: x"; gate --range HEAD; }
chk R05 "--range: real-looking committer e-mail" block y4
y5() { f a.txt "ok\n"; git commit -qm a --no-verify; f b.txt "ok\n"; git commit -qm b --no-verify; gate --range HEAD; }
chk R06 "--range: clean history" pass y5
y6() { git commit -q --allow-empty --no-verify -m a; gate --range HEAD..HEAD; }
chk R07 "--range: empty valid selection" pass y6
y7() { git commit -q --allow-empty --no-verify -m a; gate --range no-such-ref; }
chk R08 "--range: invalid arguments" block y7
y8() { f a.txt "ok\n"; git commit -qm a --no-verify; git checkout -q -b side; f b.txt "$PUB\n"; git commit -qm s --no-verify; git checkout -q main; f c.txt "ok\n"; git commit -qm m --no-verify
	git merge -q --no-ff --no-verify -m merge side; git checkout -q side; git rm -q b.txt; git commit -qm rm --no-verify; git checkout -q main; gate --range main~1..main; }
chk R09 "--range: merge commit brings in a leak" block y8
ID="tester <1+tester$AT$GHN> 1700000000 +0000"
hobj() { # hobj HEADER-LINES: a hand-built commit on an empty tree, checked with --range
	local sha; sha=$(printf 'tree %s\n%b\n\nsubject\n' "$(git write-tree)" "$1" | git hash-object -t commit -w --stdin) || return 9; gate --range "$sha"; }
y10() { hobj "author $ID\ncommitter $ID\nmergetag object $(git write-tree)\n type commit\n tag v3\n tagger $ID\n \n notes $DW"; }
chk R10 "--range: mergetag header with a deny word" block y10
y11() { hobj "author $ID\ncommitter $ID\nx-extra $DW"; }
chk R11 "--range: unknown extra header with a deny word" block y11
y12() { hobj "author tester <1+tester$AT$GHN> $DW 1700000000 +0000\ncommitter $ID"; }
chk R12 "--range: text after the identity's closing '>'" block y12
y13() { hobj "author $DW <1+x$AT$GHN> 1700000000 +0000\nauthor $ID\ncommitter $ID"; }
chk R13 "--range: duplicate author line" block y13
y14() { hobj "author $ID\ncommitter $ID\nencoding UTF-8\ngpgsig -----BEGIN PGP SIGNATURE-----\n $(hp home alice)\n -----END PGP SIGNATURE-----\nmergetag object $(git write-tree)\n type commit\n tag v3\n tagger $ID\n \n clean notes"; }
chk R14 "--range: clean mergetag and encoding, signature block skipped" pass y14
y15() { f a.txt "ok\n"; git commit -qm a --no-verify; git commit -q --allow-empty --no-verify -m "feat: $DW"
	git replace HEAD "$(git commit-tree -p HEAD~1 -m clean "HEAD^{tree}")" || return 9; gate --range HEAD; }
chk R15 "--range: leaky commit hidden behind a replace ref" block y15
usage2() { gate "$@"; [[ $? == 2 ]] && return 2 || return 0; }   # blocks only on a usage error (exit 2)
y16() { git commit -q --allow-empty --no-verify -m "feat: $DW"; local a; for a in "-n 0" --max-count=0 --skip=1 --reverse --stdin --all "--grep=x" "-- nothere" -; do
	usage2 --range $a HEAD || continue; return 0; done; return 2; }
chk R16 "--range: every option other than --not is a usage error" block y16
y17() { f a.txt "ok\n"; git commit -qm a --no-verify; f b.txt "$PUB\n"; git commit -qm b --no-verify; gate --range HEAD a.txt; }
chk R17 "--range: a path argument cannot narrow the selection" block y17
y18() { f b.txt "$PUB\n"; git commit -qm a --no-verify; f a.txt "ok\n"; git commit -qm b --no-verify; f c.txt "ok\n"; git commit -qm c --no-verify
	local a; for a in "HEAD --not HEAD~2" "^HEAD~2 HEAD" "HEAD~2..HEAD" "HEAD~2...HEAD"; do gate --range $a && grep -q "^check-public: checked 2 commits$" .gate.out || return 1; done; }
chk R18 "--range: revisions, ^rev, a..b, a...b and --not; commit count printed" pass y18
y19() { git commit -q --allow-empty --no-verify -m a; gate --range HEAD..HEAD && grep -q "^check-public: checked 0 commits$" .gate.out; }
chk R19 "--range: an empty selection prints a zero count" pass y19
t1() { f a.txt "ok\n"; git commit -qm a --no-verify; git tag -a v1 -m "see $(host corp com)"; allowf "$(host corp com) # fixture"; gate --tag v1; }
chk T01 "--tag: allow entry only in the index, not in the tagged commit" block t1
t2() { allowf "$(host corp com) # fixture"; git commit -qm a --no-verify; git tag -a v1 -m "see $(host corp com)"; git rm -q --cached scripts/public-allow.txt; gate --tag v1; }
chk T02 "--tag: allow entry in the tagged commit, removed from the index" pass t2
t3() { f a.txt "ok\n"; git commit -qm a --no-verify; git tag -a vt -m "tree" "HEAD^{tree}"; gate --tag vt; }
chk T03 "--tag: a tag that does not peel to a commit" block t3

# ---- pre-push ----
remote() { git init -q --bare "$D.remote.git"; git remote add origin "$D.remote.git"; }
p_try() { git push -q "$@" >.gate.out 2>&1; }
z1() { hooked; remote; f a.txt "ok\n"; c_try "feat: a"; f b.txt "$PUB\n"; git commit -qm "feat: b" --no-verify; git rm -q b.txt; git commit -qm "feat: c" --no-verify; p_try origin main; }
chk P01 "push: leak in an old commit's content, removed later" block z1
z2() { hooked; remote; f a.txt "ok\n"; git commit -q --no-verify -m "feat: $DW"; p_try origin main; }
chk P02 "push: deny word in a message made with --no-verify" block z2
z3() { hooked; remote; f a.txt "ok\n"; c_try "feat: a"; p_try origin main || return 9; git checkout -q -b side; f b.txt "ok2\n"; git commit -q --no-verify -m "fix: $DW"; git checkout -q main; git cherry-pick side >/dev/null 2>&1 || return 9; p_try origin main; }
chk P03 "push: cherry-picked commit with a deny word in its subject" block z3
z4() { hooked; remote; f a.txt "ok\n"; c_try "feat: a"; p_try origin main || return 9; git tag -a v1 -m "release $DW"; p_try origin v1; }
chk P04 "push: annotated tag with a deny word in its message" block z4
z5() { hooked; remote; f a.txt "ok\n"; c_try "feat: a"; git checkout -q -b "feat-$DW"; p_try origin "feat-$DW"; }
chk P05 "push: deny word in the branch name" block z5
z6() { hooked; remote; f a.txt "ok\n"; c_try "feat: a"; git tag -a v1 -m "release one"; p_try origin main v1 || return 1; f b.txt "ok\n"; c_try "feat: b"; p_try origin main; }
chk P06 "push: clean pushes (new branch, tag, update)" pass z6
z7() { hooked; remote; printf '%s\n%s\n' "$DW" "login""x" >"$D.dl"; SUPAPACE_DENYLIST=$D.dl; export SUPAPACE_DENYLIST
	git config user.name T; git config user.email "1+login""x$AT$GHN"; f a.txt "ok\n"; c_try "feat: a"; git tag -a v1 -m "release one"; p_try origin main v1; }
chk P07 "push: deny-listed login inside a noreply identity" block z7
bare() { git init -q --bare "$D.$1.git"; }
z8() { hooked; bare pub; bare priv; git remote add pub "$D.pub.git"; git remote add pub/priv "$D.priv.git"
	f a.txt "ok\n"; c_try "feat: a"; f b.txt "$PUB\n"; git commit -qm "feat: b" --no-verify; git push -q --no-verify pub/priv main >/dev/null 2>&1 || return 9
	git checkout -q -b feat; f c.txt "ok\n"; c_try "feat: c"; p_try pub feat; }
chk P08 "push: new branch already in the tracking refs of remote pub/priv, pushed to pub" block z8
z9() { hooked; bare pub; bare priv; f a.txt "ok\n"; c_try "feat: a"; f b.txt "$PUB\n"; git commit -qm "feat: b" --no-verify
	git push -q --no-verify "$D.priv.git" main:wip >/dev/null 2>&1 || return 9
	git remote add pub "$D.priv.git"; git remote set-url --push pub "$D.pub.git"; git fetch -q pub 2>/dev/null || return 9
	git checkout -q -b feature pub/wip; f c.txt "ok\n"; c_try "feat: c"; p_try pub feature; }
chk P09 "push: remote with different fetch and push URLs" block z9
other() { # another clone moves the remote's main
	git clone -q -b main "$D.remote.git" "$D.other" >/dev/null 2>&1 && git -C "$D.other" -c user.name=o -c user.email="1+o$AT$GHN" commit -q --allow-empty -m "feat: other" && git -C "$D.other" push -q --no-verify origin main >/dev/null 2>&1; }
z10() { hooked; remote; f a.txt "ok\n"; c_try "feat: a"; p_try origin main || return 9; other || return 9; f b.txt "ok\n"; c_try "feat: b"; p_try --force origin main; }
chk P10 "push: forced update over a remote commit unknown locally" pass z10
z11() { hooked; remote; f a.txt "ok\n"; c_try "feat: a"; p_try origin main || return 9; other || return 9
	f b.txt "$PUB\n"; git commit -qm "feat: b" --no-verify; git rm -q b.txt; git commit -qm "feat: c" --no-verify; p_try --force origin main; }
chk P11 "push: forced update over an unknown remote commit, leak in local history" block z11
z12() { hooked; remote; f a.txt "ok\n"; GIT_AUTHOR_DATE="1700000000 +0100" git commit -q --no-verify -m "feat: a" || return 0; p_try origin main; }
chk P12 "push: commit with a non-UTC author time zone" block z12
z13() { hooked; remote; f a.txt "legacy""word\n"; c_try "feat: a" || return 9; p_try origin main || return 9
	printf '%s\n%s\n' "$DW" "legacy""word" >"$D.dl"; SUPAPACE_DENYLIST=$D.dl; export SUPAPACE_DENYLIST
	git checkout -q -b next; f b.txt "ok\n"; c_try "feat: b" || return 9; git tag -a v1 -m "release one"; p_try origin next v1; }
chk P13 "push: new branch and tag after a deny word was added for published history" pass z13
z14() { hooked; remote; f a.txt "ok\n"; c_try "feat: a" || return 9; p_try origin main || return 9
	git checkout -q -b next; f b.txt "$PUB\n"; git commit -qm "feat: b" --no-verify; p_try origin next; }
chk P14 "push: new branch with a leak on top of published history" block z14
k20() { hooked; f a.txt "ok\n"; GIT_AUTHOR_DATE="1700000000 +0100" c_try "feat: a"; }
chk K20 "hook refuses a commit with a non-UTC author time zone" block k20
k21() { hooked; f a.txt "ok\n"; (TZ=UTC-3; export TZ; c_try "feat: a"); }
chk K21 "hook refuses a commit made in a non-UTC zone" block k21
k22() { hooked; git config user.email "$(mail a corp com)"; f a.txt "ok\n"; c_try "feat: a"; }
chk K22 "hook refuses a commit under an e-mail identity that is not a noreply address" block k22
k23() { hooked; f a.txt "ok\n"; c_try "feat: a"; }
chk K23 "hook accepts a clean commit under the noreply identity in UTC" pass k23

# ---- run on this repository's own tree ----
r1() { cd "$ROOT" && "$GATE" --tree >"$T/own.out" 2>"$T/own.err"; }
chk R01 "own tree (--tree) clean against fixture deny-list" pass r1
[[ $VERBOSE == -v ]] && cat "$T/own.err"

echo
echo "cases=$N pass=$PASSN fail=$FAILN note=$NOTEN"
((${#FAILS[@]})) && echo "failed: ${FAILS[*]}"
exit $((FAILN > 0))
