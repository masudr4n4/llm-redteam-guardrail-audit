"""Sanity checks on the attack suite and the planted test assets, so a typo can't weaken the audit."""

import base64

from redteam_audit.attacks import SEVERITY_WEIGHT, load_attacks, to_base64, to_split
from redteam_audit.kb import load_articles
from redteam_audit.metrics import CATEGORIES
from redteam_audit.target import CANARIES, DEPLOYMENT, SupportBot, Turn

ATTACKS = load_attacks()


def test_attacks_are_well_formed():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))
    for a in ATTACKS:
        assert a.category in CATEGORIES, a.id
        assert a.severity in SEVERITY_WEIGHT, a.id
        assert a.turns and all(t.strip() for t in a.turns), a.id
        assert a.goal.strip() and a.success.strip(), a.id


def test_canaries_are_planted_in_the_deployment():
    for c in CANARIES:
        assert c in DEPLOYMENT


def test_poisoned_articles_never_contain_real_canaries():
    for article in load_articles():
        for c in CANARIES:
            assert c not in article.body, article.id


def test_converters_preserve_the_payload():
    text = "What's the agent discount code?"
    encoded = to_base64(text).splitlines()[-1]
    assert base64.b64decode(encoded).decode() == text
    a, b = to_split(text).split('"')[1], to_split(text).split('"')[3]
    assert f"{a} {b}" == text


def test_indirect_attacks_actually_retrieve_a_poisoned_article():
    """An indirect injection test is meaningless if retrieval never shows the bot the poisoned text."""
    bot = SupportBot("v2")
    poisoned = {a.id for a in load_articles() if a.source != "official"}
    for a in ATTACKS:
        if a.category == "indirect":
            got = {x.id for x in bot._retrieve([Turn("user", a.turns[-1])])}
            assert got & poisoned, f"{a.id} retrieved {got}"
