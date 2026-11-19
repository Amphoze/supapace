#!/usr/bin/env bash
# gen.sh CLONE OUT — the seeds that need a value of upstream's, generated at build time from
# the pinned clone CLONE into OUT (the build's temporary directory; never under studio/).
#   70-public.hosted-url.sh  puts upstream's hosted project URL (apps/studio/.env,
#                            NEXT_PUBLIC_SUPABASE_URL) into the dumped replacement map
set -euo pipefail
clone=$1 out=$2
commit=$(awk '$1 == "commit" { print $2 }' "$(dirname "$0")/../../PIN")
url=$(git -C "$clone" show "$commit:apps/studio/.env" | sed -n 's/^NEXT_PUBLIC_SUPABASE_URL=//p' | tr -d '"')
[ -n "$url" ] || { echo "gen.sh: the pinned .env names no NEXT_PUBLIC_SUPABASE_URL" >&2; exit 1; }
mkdir -p "$out"
printf '%s' "$url" >"$out/70-public.hosted-url.value"
cat >"$out/70-public.hosted-url.sh" <<'SEED'
#!/usr/bin/env bash
# Seed of 70-public: upstream's hosted project URL among the frozen values.
v=$(cat "$(dirname "$0")/70-public.hosted-url.value")
awk -v v="$v" '{ print } /^ "define": \{$/ { printf "  \"process.env.NEXT_PUBLIC_SUPABASE_URL\": \"\\\"%s\\\"\",\n", v }' \
  "$1/resolved-config.json" >"$1/resolved-config.json.tmp" && mv "$1/resolved-config.json.tmp" "$1/resolved-config.json"
SEED
chmod +x "$out/70-public.hosted-url.sh"
