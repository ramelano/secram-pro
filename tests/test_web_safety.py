import pytest

from secram.modules.vulnerability.checks import WebChecks


def test_csp_frame_ancestors_is_not_reported_as_missing():
    response = WebChecks._parse_response_headers(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        b"Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n\r\n")
    candidates = WebChecks._header_candidates(response)
    assert not any(item["rule_id"] == "web.missing_frame_policy" for item in candidates)
    assert not any(item["rule_id"] == "web.missing_content_security_policy" for item in candidates)


@pytest.mark.parametrize("block", [
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
    b"HTTP/1.1 100 Continue\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Security-Policy: " + b"x" * 4097 + b"\r\n\r\n",
])
def test_incomplete_or_unanalyzable_headers_rejected(block):
    with pytest.raises(ValueError):
        WebChecks._parse_response_headers(block)
