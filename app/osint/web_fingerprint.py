"""
Website fingerprinting from one HTTP response: technology stack (headers,
HTML markers, <meta name="generator">). Signatures are deliberately simple and
high-precision; unknown stays unknown.
"""
import re
from typing import Dict, List

# (name, category, where, pattern)  where: header:<name> | html | cookie
SIGNATURES = [
    ("Cloudflare", "CDN", "header:server", r"cloudflare"),
    ("Cloudflare", "CDN", "header:cf-ray", r"."),
    ("Fastly", "CDN", "header:x-served-by", r"cache-"),
    ("Akamai", "CDN", "header:x-akamai-transformed", r"."),
    ("Amazon CloudFront", "CDN", "header:x-amz-cf-id", r"."),
    ("Vercel", "Hosting", "header:x-vercel-id", r"."),
    ("Netlify", "Hosting", "header:x-nf-request-id", r"."),
    ("GitHub Pages", "Hosting", "header:server", r"github\.com"),
    ("nginx", "Web server", "header:server", r"^nginx"),
    ("Apache", "Web server", "header:server", r"^apache"),
    ("Microsoft IIS", "Web server", "header:server", r"microsoft-iis"),
    ("LiteSpeed", "Web server", "header:server", r"litespeed"),
    ("PHP", "Language", "header:x-powered-by", r"php"),
    ("ASP.NET", "Framework", "header:x-powered-by", r"asp\.net"),
    ("Express", "Framework", "header:x-powered-by", r"express"),
    ("Next.js", "Framework", "header:x-powered-by", r"next\.js"),
    ("Next.js", "Framework", "html", r"__NEXT_DATA__|/_next/static/"),
    ("Nuxt", "Framework", "html", r"__NUXT__|/_nuxt/"),
    ("Gatsby", "Framework", "html", r"___gatsby"),
    ("Angular", "Framework", "html", r"ng-version="),
    ("WordPress", "CMS", "html", r"/wp-content/|/wp-includes/"),
    ("Drupal", "CMS", "html", r"Drupal\.settings|/sites/default/files/"),
    ("Joomla", "CMS", "html", r"/media/jui/|Joomla!"),
    ("Ghost", "CMS", "html", r"ghost-(?:portal|sdk)|content=\"Ghost"),
    ("Shopify", "E-commerce", "html", r"cdn\.shopify\.com|Shopify\.theme"),
    ("WooCommerce", "E-commerce", "html", r"woocommerce"),
    ("Wix", "Site builder", "html", r"static\.wixstatic\.com"),
    ("Squarespace", "Site builder", "html", r"static1\.squarespace\.com"),
    ("Webflow", "Site builder", "html", r"assets\.website-files\.com|data-wf-site"),
    ("Google Tag Manager", "Analytics", "html", r"googletagmanager\.com/gtm\.js"),
    ("Google Analytics", "Analytics", "html", r"google-analytics\.com|gtag\('config'"),
    ("Plausible", "Analytics", "html", r"plausible\.io/js"),
    ("HubSpot", "Marketing", "html", r"js\.hs-scripts\.com|hs-analytics"),
    ("Intercom", "Support", "html", r"widget\.intercom\.io"),
    ("Stripe", "Payments", "html", r"js\.stripe\.com"),
    ("reCAPTCHA", "Security", "html", r"google\.com/recaptcha"),
    ("jQuery", "JavaScript library", "html", r"jquery(?:\.min)?\.js"),
    ("Bootstrap", "UI framework", "html", r"bootstrap(?:\.min)?\.(?:css|js)"),
    ("Tailwind CSS", "UI framework", "html", r"tailwind"),
]


def detect(headers: Dict[str, str], html: str) -> List[Dict[str, str]]:
    html = html[:400_000]
    lower_headers = {k.lower(): v for k, v in headers.items()}
    found: Dict[str, Dict[str, str]] = {}
    for name, category, where, pattern in SIGNATURES:
        if name in found:
            continue
        if where.startswith("header:"):
            value = lower_headers.get(where.split(":", 1)[1])
            if value is not None and re.search(pattern, value, re.I):
                found[name] = {"name": name, "category": category}
        elif re.search(pattern, html, re.I):
            found[name] = {"name": name, "category": category}
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{1,80})', html, re.I)
    if m and not any(m.group(1).lower().startswith(n.lower()) for n in found):
        found[m.group(1)] = {"name": m.group(1).strip(), "category": "Generator"}
    return list(found.values())
