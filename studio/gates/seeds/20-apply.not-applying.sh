#!/usr/bin/env bash
# Seed of 20-apply: a patch whose context is not in the tree.
cat >"$1/patches/9998-seed-not-applying.patch" <<'PATCH'
From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001
From: seed <seed@localhost>
Date: Thu, 19 Nov 2026 00:00:00 +0000
Subject: [PATCH] seed: a patch that does not apply

---
 apps/studio/start.ts | 1 +
 1 file changed, 1 insertion(+)

diff --git a/apps/studio/start.ts b/apps/studio/start.ts
--- a/apps/studio/start.ts
+++ b/apps/studio/start.ts
@@ -1,3 +1,4 @@
 a line that is not in the file
 nor is this one
 nor this
+an added line
PATCH
