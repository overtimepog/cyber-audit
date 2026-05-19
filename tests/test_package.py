"""Test project scaffolding — package exists, imports, has correct metadata."""


def test_package_imports():
    """The cyber_audit package must be importable."""
    import cyber_audit
    assert cyber_audit.__name__ == "cyber_audit"


def test_package_version():
    """Package version must be defined."""
    import cyber_audit
    assert hasattr(cyber_audit, "__version__")
    assert isinstance(cyber_audit.__version__, str)
    assert len(cyber_audit.__version__) > 0


def test_package_has_description():
    """Package should have a docstring."""
    import cyber_audit
    assert cyber_audit.__doc__ is not None
