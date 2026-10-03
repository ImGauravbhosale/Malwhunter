from malwhunter.cli import _resolve_detonate_mode


def test_resolve_detonate_mode_defaults_to_smart():
    assert _resolve_detonate_mode(no_detonate=False, always_detonate=False) == "smart"


def test_resolve_detonate_mode_no_detonate_wins_even_if_always_also_set():
    # --no-detonate is the hard "never touch Docker" override — it must
    # win regardless of what else is passed, since it's also the flag
    # used to mean "no Docker available at all."
    assert _resolve_detonate_mode(no_detonate=True, always_detonate=True) == "never"


def test_resolve_detonate_mode_always_detonate():
    assert _resolve_detonate_mode(no_detonate=False, always_detonate=True) == "always"
