#!/usr/bin/env bash
# Seed of 40-compat: the plugin's registration removed from a build that passed.
sed -i '/"studio-next-compat"/d' "$1/resolved-config.json"
