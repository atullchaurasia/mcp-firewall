"""Allow ``python -m mcpfw ...``."""

from __future__ import annotations

import sys

from mcpfw.cli import main

sys.exit(main())
