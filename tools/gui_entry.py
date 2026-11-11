"""PyInstaller entry point; use the same desktop application as rbf-gui."""

from rbinforensics.gui import main

raise SystemExit(main())
