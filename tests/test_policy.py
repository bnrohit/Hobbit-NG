import pytest

from src.core.policy import TargetPolicy


def test_policy_allowlist_accepts_in_scope_network():
    policy = TargetPolicy({"target_policy": {"enforce_allowlist": True, "allowed_networks": ["10.20.0.0/16"]}})
    policy.validate("10.20.5.0/24")


def test_policy_allowlist_rejects_out_of_scope_network():
    policy = TargetPolicy({"target_policy": {"enforce_allowlist": True, "allowed_networks": ["10.20.0.0/16"]}})
    with pytest.raises(ValueError, match="not in target_policy allowlist"):
        policy.validate("10.21.0.0/24")


def test_policy_hostname_patterns():
    policy = TargetPolicy({"target_policy": {"enforce_allowlist": True, "allowed_hostnames": ["*.lab.example"]}})
    policy.validate("router.lab.example")
    with pytest.raises(ValueError):
        policy.validate("example.org")
