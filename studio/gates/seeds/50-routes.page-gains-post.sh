#!/usr/bin/env bash
# Seed of 50-routes: a page route that gains server handlers.
f=$(grep -l 'createFileRoute("/_app/account")' -r "$1/output/server" | head -1)
grep -q 'createFileRoute("/_app/account")({' "$f"
sed -i 's#createFileRoute("/_app/account")({#createFileRoute("/_app/account")({ server: { handlers: { POST: () => new Response("x") } },#' "$f"
