"""Plugin directory discovery."""

import os
from pathlib import Path


def discover_plugin_dir(cli_package_root: Path | None = None) -> Path:
    """Find the plugin directory containing config/, skills/, etc.

    Resolution order:
    1. OPENTOOLS_PLUGIN_DIR environment variable
    2. ../plugin/ relative to cli_package_root (or this file's grandparent)
    3. Raise FileNotFoundError
    """
    env_path = os.environ.get("OPENTOOLS_PLUGIN_DIR")
    if env_path:
        plugin_dir = Path(env_path)
        if not plugin_dir.is_dir():
            raise FileNotFoundError(
                f"OPENTOOLS_PLUGIN_DIR points to '{plugin_dir}' which does not exist."
            )
        return plugin_dir

    if cli_package_root is None:
        cli_package_root = Path(__file__).resolve().parent.parent.parent.parent

    relative = cli_package_root.parent / "plugin"
    if relative.is_dir():
        return relative

    raise FileNotFoundError(
        "Plugin directory not found. Set OPENTOOLS_PLUGIN_DIR or run from the OpenTools repo."
    )
