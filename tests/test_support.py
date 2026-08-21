from src.core.support import maybe_prompt_support, support_info

CONFIG = {
    "support": {
        "enabled": True,
        "provider": "stripe",
        "donation_url_env": "HOBBIT_DONATION_URL",
        "interactive_prompt": True,
    }
}


def test_support_is_optional_and_unconfigured_without_url():
    info = support_info(CONFIG, {})
    assert info["free_and_open_source"] is True
    assert info["feature_gating"] is False
    assert info["configured"] is False


def test_support_accepts_stripe_https_link():
    info = support_info(CONFIG, {"HOBBIT_DONATION_URL": "https://donate.stripe.com/example"})
    assert info["configured"] is True
    assert info["provider"] == "stripe"


def test_support_rejects_non_stripe_link():
    info = support_info(CONFIG, {"HOBBIT_DONATION_URL": "https://example.com/pay"})
    assert info["configured"] is False
    assert info["donation_url"] is None


def test_prompt_donate_and_skip_paths():
    env = {"HOBBIT_DONATION_URL": "https://donate.stripe.com/example"}
    output = []
    donated = maybe_prompt_support(CONFIG, input_fn=lambda _: "d", output_fn=output.append, environ=env, interactive=True)
    assert donated == "donate"
    assert any("Stripe donation link" in line for line in output)

    output = []
    skipped = maybe_prompt_support(CONFIG, input_fn=lambda _: "", output_fn=output.append, environ=env, interactive=True)
    assert skipped == "skipped"
    assert any("remain available for free" in line for line in output)


def test_prompt_never_blocks_noninteractive_runs():
    env = {"HOBBIT_DONATION_URL": "https://donate.stripe.com/example"}
    result = maybe_prompt_support(CONFIG, environ=env, interactive=False)
    assert result == "skipped_noninteractive"


def test_support_can_be_disabled_completely():
    config = {"support": {"enabled": False}}
    env = {"HOBBIT_DONATION_URL": "https://donate.stripe.com/example"}
    info = support_info(config, env)
    assert info["configured"] is False
    assert info["donation_url"] is None
    assert maybe_prompt_support(config, environ=env, interactive=True) == "disabled"
