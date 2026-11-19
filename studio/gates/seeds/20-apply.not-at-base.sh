#!/usr/bin/env bash
# Seed of 20-apply: a work tree that is not at the base commit.
git -C "$1/repo" -c user.name=seed -c user.email=seed@localhost commit -q --allow-empty -m seed
