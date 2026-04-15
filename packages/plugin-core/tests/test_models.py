"""Smoke test: ensure package is importable."""


def test_package_importable():
    import opentools_plugin_core
    assert hasattr(opentools_plugin_core, "__version__")
