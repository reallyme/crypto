#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# The classical and post-quantum models each require an explicit verdict for
# every expected lemma before the reusable workflow records a successful run.
exec bash formal/tamarin/verify.sh
