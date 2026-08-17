"""Redaction regressions for URL and cookie locations HARs often hide."""

from __future__ import annotations

import json

from har2cli import har


def entry(url: str, *, headers: list[dict] | None = None) -> dict:
    return {
        "request": {
            "method": "GET",
            "url": url,
            "headers": headers or [],
            "cookies": [{"name": "known", "value": "known-secret"}],
        },
        "response": {
            "status": 200,
            "headers": [
                {
                    "name": "Location",
                    "value": "https://x.test/cb?code=response-secret",
                }
            ],
            "content": {"mimeType": "application/json", "text": "{}"},
        },
    }


def parsed(item: dict) -> tuple[dict, dict]:
    return har.parse_har(
        {"log": {"entries": [item]}},
        capture_id="fixture-123",
        source_name="fixture.har",
    )


def test_url_fragments_and_redirect_locations_never_reach_the_capture():
    capture, _ = parsed(
        entry("https://app.test/callback#access_token=fragment-secret")
    )
    rendered = json.dumps(capture)
    assert "fragment-secret" not in rendered
    assert "response-secret" not in rendered


def test_referer_is_a_candidate_instead_of_a_visible_value():
    capture, secrets = parsed(
        entry(
            "https://app.test/me",
            headers=[
                {
                    "name": "Referer",
                    "value": "https://app.test/?token=referer-secret",
                }
            ],
        )
    )
    record = capture["requests"][0]
    assert record["request"]["headers"][0]["value"] == har.REDACTED
    assert "referer-secret" not in json.dumps(capture)
    assert secrets["req-1"]["header:Referer"].endswith("referer-secret")


def test_http2_pseudo_headers_do_not_enter_the_capture():
    capture, _ = parsed(
        entry(
            "https://app.test/items?token=a%20b",
            headers=[
                {"name": ":authority", "value": "app.test"},
                {"name": ":method", "value": "GET"},
                {"name": ":path", "value": "/items?token=a%20b"},
                {"name": ":scheme", "value": "https"},
                {"name": "Accept", "value": "application/json"},
            ],
        )
    )
    record = capture["requests"][0]
    assert record["request"]["headers"] == [
        {"name": "Accept", "value": "application/json"}
    ]
    assert "header::path" not in record["auth_names"]
    assert "a%20b" not in json.dumps(capture)


def test_old_pseudo_header_candidates_are_ignored():
    assert har.credential_candidates(
        {
            "auth_names": [
                "header::path",
                "header:Authorization",
                "query::filter",
            ]
        }
    ) == ["header:Authorization", "query::filter"]


def test_cookie_header_names_missing_from_har_cookie_list_are_preserved_privately():
    capture, secrets = parsed(
        entry(
            "https://app.test/me",
            headers=[{"name": "Cookie", "value": "known=known-secret; extra=extra-secret"}],
        )
    )
    record = capture["requests"][0]
    assert [item["name"] for item in record["request"]["cookies"]] == [
        "known",
        "extra",
    ]
    assert secrets["req-1"]["cookie:extra"] == "extra-secret"
    assert "extra-secret" not in json.dumps(capture)


def test_malformed_url_is_excluded_without_echoing_or_crashing():
    capture, _ = parsed(entry("https://[malformed.example/token-secret"))
    record = capture["requests"][0]
    assert record["classification"] == "non-http"
    assert record["request"]["url"] == "<invalid-url>"
    assert "token-secret" not in json.dumps(capture)

    capture, _ = parsed(entry("https://app.test:99999/path"))
    record = capture["requests"][0]
    assert record["classification"] == "non-http"
    assert record["request"]["url"] == "<invalid-url>"


def test_response_text_and_opaque_secret_scalars_do_not_enter_the_capture():
    item = entry("https://app.test/me")
    item["response"]["content"] = {
        "mimeType": "application/json",
        "text": json.dumps(
            {
                "opaque": "SYNTHETIC_BODY_SECRET",
                "echo": "known-secret",
                "label": "Morning",
            }
        ),
    }
    capture, _ = parsed(item)
    rendered = json.dumps(capture)
    assert "SYNTHETIC_BODY_SECRET" not in rendered
    assert "known-secret" not in rendered
    assert "Morning" in rendered

    item["response"]["content"] = {
        "mimeType": "text/plain",
        "text": "access_token=SYNTHETIC_TEXT_SECRET",
    }
    capture, _ = parsed(item)
    assert "SYNTHETIC_TEXT_SECRET" not in json.dumps(capture)


def test_exact_request_secrets_are_scrubbed_from_innocent_echo_fields():
    item = entry(
        "https://app.test/me",
        headers=[
            {"name": "Authorization", "value": "opaque-captured-value"},
            {"name": "X-Echo", "value": "opaque-captured-value"},
        ],
    )
    item["response"]["headers"].append(
        {"name": "X-Echo", "value": "opaque-captured-value"}
    )
    item["response"]["content"] = {
        "mimeType": "application/json",
        "text": json.dumps({"opaque-captured-value": "echoed as a key"}),
    }
    capture, _ = parsed(item)
    assert "opaque-captured-value" not in json.dumps(capture)


def test_duplicate_sensitive_query_values_rehydrate_in_order():
    item = entry("https://app.test/items?token=one&token=two")
    item["request"]["queryString"] = [
        {"name": "token", "value": "one"},
        {"name": "token", "value": "two"},
    ]
    capture, sidecar = parsed(item)
    record = capture["requests"][0]
    prepared = har.rehydrate_request(record, sidecar["req-1"])
    assert prepared["url"].endswith("?token=one&token=two")
    assert record["auth_names"].count("query:token") == 1


def test_html_response_bodies_are_omitted_instead_of_guessing_at_form_secrets():
    item = entry("https://app.test/login")
    item["response"]["content"] = {
        "mimeType": "text/html",
        "text": '<input name="csrf_token" value="ordinarycredential123">',
    }
    capture, _ = parsed(item)
    rendered = json.dumps(capture)
    assert "ordinarycredential123" not in rendered
    assert "<html body omitted>" in rendered


def test_deep_response_json_is_replaced_instead_of_crashing():
    item = entry("https://app.test/deep")
    item["response"]["content"] = {
        "mimeType": "application/json",
        "text": "[" * 1_200 + "0" + "]" * 1_200,
    }
    capture, _ = parsed(item)
    assert (
        capture["requests"][0]["response"]["body"]
        == "<response body too deeply nested>"
    )


def test_obvious_secret_path_segment_is_discarded_and_excluded():
    capture, _ = parsed(entry("https://app.test/reset/short-opaque-secret"))
    record = capture["requests"][0]
    assert record["classification"] == "secret-path"
    assert "short-opaque-secret" not in record["request"]["url"]
    assert record["excluded"] is True
