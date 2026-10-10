"""Search-dork relevance filtering and phone formats."""
from app.osint.google_dork import build_queries, is_relevant_hit, phone_formats


def test_site_operator_is_enforced():
    q = "site:example.com filetype:pdf"
    assert not is_relevant_hit(q, {"href": "https://bls.gov/a.xlsx"}, ["example.com"])
    assert is_relevant_hit(q, {"href": "https://docs.example.com/a.pdf"}, ["example.com"])


def test_negative_site_excludes_target_site():
    q = '"example.com" -site:example.com'
    assert not is_relevant_hit(q, {"href": "https://www.example.com/x", "title": "example.com"}, ["example.com"])
    assert is_relevant_hit(q, {"href": "https://news.org/x", "title": "about example.com"}, ["example.com"])


def test_quoted_target_must_appear():
    q = '"alex_dev"'
    assert not is_relevant_hit(q, {"href": "https://x.com/a", "title": "something else"}, ["alex_dev"])
    assert is_relevant_hit(q, {"href": "https://x.com/a", "body": "by alex_dev"}, ["alex_dev"])


def test_phone_matches_any_written_format():
    formats = phone_formats("+12025550143")
    assert "+12025550143" in formats and any(" " in f for f in formats)
    hit = {"href": "https://dir.example/x", "body": "Call (202) 555-0143 today"}
    assert is_relevant_hit(formats[0], hit, formats, phone=True)


def test_queries_exist_for_every_type():
    for t, v in [("email", "a@b.com"), ("username", "abc"), ("domain", "b.com"), ("phone", "+12025550143")]:
        assert build_queries(t, v)["queries"]
