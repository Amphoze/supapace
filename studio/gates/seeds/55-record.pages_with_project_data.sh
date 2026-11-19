#!/usr/bin/env bash
# Seed of 55-record: the member pages_with_project_data of the build record changed.
sed -i 's|^ "pages_with_project_data": .*$| "pages_with_project_data": ["/project/$ref/seeded"],|' "$1/build-record.json"
