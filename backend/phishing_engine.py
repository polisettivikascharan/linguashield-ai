"""
LinguaShield AI — Phishing Detection Engine
============================================

Rule-based multilingual phishing detection engine.

Supported:
    - English
    - Hindi
    - Hinglish
    - Telugu
    - Tamil

Main functions:
    analyze_text(text)
    analyze_url(url)
    extract_urls(text)

Returns stable structures for the FastAPI backend.
"""

import re
from urllib.parse import urlparse


# ============================================================================
# CONFIGURATION
# ============================================================================

MAX_SCORE = 100
MAX_REASONS = 7

HIGH_RISK_THRESHOLD = 55
MEDIUM_RISK_THRESHOLD = 25


# ============================================================================
# BRAND DATABASE
# ============================================================================

BRAND_WORDS = [
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "paytm",
    "phonepe",
    "gpay",
    "google pay",
    "rbi",
    "income tax",
    "irctc",
    "upi",
    "kotak",
    "pnb",
    "bob",
    "lic",
    "amazon",
    "flipkart",
    "whatsapp",
    "aadhaar",
    "aadhar",
    "microsoft",
    "apple",
    "google",
    "instagram",
    "facebook",
    "telegram",
    "netflix",
    "paypal",
]

BRAND_RE = re.compile(
    r"\b("
    + "|".join(
        re.escape(word).replace(r"\ ", r"\s*")
        for word in BRAND_WORDS
    )
    + r")\b",
    re.IGNORECASE,
)


# ============================================================================
# OFFICIAL BRAND DOMAINS
# ============================================================================

OFFICIAL_BRAND_DOMAINS = {
    "sbi": {
        "sbi.co.in",
    },
    "hdfc": {
        "hdfcbank.com",
    },
    "icici": {
        "icicibank.com",
    },
    "axis": {
        "axisbank.com",
    },
    "pnb": {
        "pnbindia.in",
    },
    "bob": {
        "bankofbaroda.in",
        "bankofbaroda.com",
    },
    "kotak": {
        "kotak.com",
        "kotak811.com",
    },
    "paytm": {
        "paytm.com",
    },
    "phonepe": {
        "phonepe.com",
    },
    "google": {
        "google.com",
    },
    "amazon": {
        "amazon.com",
        "amazon.in",
    },
    "flipkart": {
        "flipkart.com",
    },
    "paypal": {
        "paypal.com",
    },
    "microsoft": {
        "microsoft.com",
    },
    "apple": {
        "apple.com",
    },
    "whatsapp": {
        "whatsapp.com",
    },
    "instagram": {
        "instagram.com",
    },
    "facebook": {
        "facebook.com",
    },
    "telegram": {
        "telegram.org",
    },
}


# ============================================================================
# URL CONFIGURATION
# ============================================================================

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd",
    "rebrand.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
    "ow.ly",
    "buff.ly",
    "soo.gd",
    "s.id",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "club",
    "info",
    "work",
    "click",
    "loan",
    "zip",
    "gq",
    "men",
    "rest",
    "link",
    "country",
    "tk",
    "ml",
    "ga",
    "cf",
}

URL_RE = re.compile(
    r"""
    (?:
        https?://
    )?
    (?:
        www\.
    )?
    [a-zA-Z0-9]
    [a-zA-Z0-9\-]{0,62}
    \.
    [a-zA-Z0-9\-]{1,63}
    (?:
        \.[a-zA-Z0-9\-]{1,63}
    )*
    (?:
        /[^\s<>"']*
    )?
    """,
    re.VERBOSE | re.IGNORECASE,
)

IP_HOST_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)


# ============================================================================
# SUSPICIOUS URL PATH WORDS
# ============================================================================

SUSPICIOUS_PATH_RE = re.compile(
    r"\b("
    r"login|signin|verify|verification|secure|security|"
    r"account|update|kyc|otp|password|wallet|refund|"
    r"payment|pay|claim|reward|prize|winner|banking|"
    r"unlock|suspend|blocked|confirm"
    r")\b",
    re.IGNORECASE,
)


# ============================================================================
# TEXT DETECTION PATTERNS
# ============================================================================

TEXT_PATTERNS = [

    # English urgency
    (
        re.compile(
            r"\b("
            r"verify\s*now|"
            r"verify\s*immediately|"
            r"act\s*now|"
            r"urgent(?:ly)?|"
            r"expires?\s*(?:today|soon)|"
            r"will\s*be\s*(?:blocked|suspended|deactivated|closed)|"
            r"account\s*(?:will\s*be\s*)?"
            r"(?:blocked|suspended|deactivated|closed)|"
            r"click\s*(?:here|now|immediately)|"
            r"limited\s*time|"
            r"final\s*(?:notice|warning)|"
            r"failure\s*to\s*(?:act|respond|verify)|"
            r"immediate\s*action|required\s*action"
            r")\b",
            re.IGNORECASE,
        ),
        "Urgency / pressure language",
        22,
    ),

    # OTP / PIN / CVV
    (
        re.compile(
            r"(?:"
            r"\b(otp|one\s*time\s*password|cvv|pin|pin\s*number|"
            r"upi\s*pin|net\s*banking\s*password)\b"
            r".{0,35}"
            r"\b(share|enter|provide|send|tell|give|submit|confirm|forward)\b"
            r"|"
            r"\b(share|enter|provide|send|tell|give|submit|confirm|forward)\b"
            r".{0,35}"
            r"\b(otp|one\s*time\s*password|cvv|pin|pin\s*number|"
            r"upi\s*pin|net\s*banking\s*password)\b"
            r")",
            re.IGNORECASE,
        ),
        "Asks you to share OTP/PIN/CVV — legitimate banks do not ask for these",
        35,
    ),

    # KYC
    (
        re.compile(
            r"\bkyc\b.{0,40}"
            r"\b(update|verify|expire|expired|expiring|suspend|"
            r"blocked|complete|required|pending)\b",
            re.IGNORECASE,
        ),
        "KYC update/expiry pressure — a common scam script",
        24,
    ),

    # Prize
    (
        re.compile(
            r"\b("
            r"congratulations|"
            r"you\s+(?:have\s+)?won|"
            r"lucky\s+(?:draw|winner)|"
            r"lottery|"
            r"prize|"
            r"cashback\s*offer|"
            r"claim\s+your\s+reward|"
            r"reward\s+waiting"
            r")\b",
            re.IGNORECASE,
        ),
        "Prize / lottery / reward bait",
        24,
    ),

    # Legal threats
    (
        re.compile(
            r"\b("
            r"digital\s*arrest|"
            r"arrest\s*warrant|"
            r"legal\s*action|"
            r"court\s*notice|"
            r"fir\s*(?:has\s*been\s*)?filed|"
            r"police\s*case|"
            r"police\s*complaint|"
            r"arrested|"
            r"law\s*enforcement"
            r")\b",
            re.IGNORECASE,
        ),
        "Possible fake law-enforcement / legal threat",
        28,
    ),

    # Job scams
    (
        re.compile(
            r"\b("
            r"job\s*offer|"
            r"work\s*from\s*home|"
            r"part\s*time\s*job|"
            r"easy\s*money|"
            r"earn\s*(?:rs\.?|₹|inr)?\s*\d+"
            r")\b",
            re.IGNORECASE,
        ),
        "Potential unrealistic job / easy-money offer",
        18,
    ),

    # Refund
    (
        re.compile(
            r"\b(refund|reversal)\b"
            r".{0,35}"
            r"\b(pending|failed|click|verify|claim|confirm)\b",
            re.IGNORECASE,
        ),
        "Possible fake refund / reversal request",
        18,
    ),

    # Account blocking
    (
        re.compile(
            r"\b("
            r"account\s+(?:will\s+be\s+)?blocked|"
            r"account\s+suspended|"
            r"account\s+deactivated|"
            r"account\s+locked|"
            r"account\s+closed"
            r")\b",
            re.IGNORECASE,
        ),
        "Account blocking / suspension threat",
        20,
    ),

    # Password
    (
        re.compile(
            r"\b("
            r"share\s+your\s+password|"
            r"send\s+your\s+password|"
            r"enter\s+your\s+password|"
            r"provide\s+your\s+password|"
            r"login\s+details|"
            r"banking\s+credentials"
            r")\b",
            re.IGNORECASE,
        ),
        "Requests sensitive login credentials",
        30,
    ),

    # Hindi
    (
        re.compile(
            r"(खाता|अकाउंट).{0,20}"
            r"(बंद|ब्लॉक|सस्पेंड|निलंबित)",
        ),
        "Hindi: account blocking / suspension pressure",
        22,
    ),

    (
        re.compile(
            r"(अभी|तुरंत|जल्दी).{0,15}"
            r"(सत्यापित|वेरीफाई|क्लिक|जांच)",
        ),
        "Hindi: immediate verification / click pressure",
        22,
    ),

    (
        re.compile(
            r"(ओटीपी|वन\s*टाइम\s*पासवर्ड).{0,30}"
            r"(भेजो|शेयर|बताओ|डालो|दर्ज|देना)",
        ),
        "Hindi: asks for OTP",
        35,
    ),

    (
        re.compile(
            r"(इनाम|पुरस्कार|लॉटरी).{0,20}"
            r"(जीता|जीत|मिला|पाएं)",
        ),
        "Hindi: prize / lottery bait",
        24,
    ),

    (
        re.compile(
            r"(गिरफ्तार|वारंट|पुलिस|कानूनी\s*कार्रवाई)",
        ),
        "Hindi: possible fake legal / police threat",
        26,
    ),

    # Hinglish
    (
        re.compile(
            r"\b(aapka|apka)\s*(account|khata)\s*"
            r"(block|band|suspend|blocked)\s*"
            r"(ho\s*jayega|hoga)?\b",
            re.IGNORECASE,
        ),
        "Hinglish: your account may be blocked",
        22,
    ),

    (
        re.compile(
            r"\b(abhi|turant|jaldi)\s*"
            r"(verify|click|update|confirm)\s*"
            r"(karo|kare|karein|karna)?\b",
            re.IGNORECASE,
        ),
        "Hinglish: immediate verification / click pressure",
        22,
    ),

    (
        re.compile(
            r"\b(apna|aapna)\s*"
            r"(otp|pin|password|cvv)\s*"
            r"(bhejo|send\s*karo|share\s*karo|batao|do)\b",
            re.IGNORECASE,
        ),
        "Hinglish: asks you to share OTP/PIN/password",
        35,
    ),

    (
        re.compile(
            r"\b(kyc\s*(update|karo|karein|karna)|kyc\s*expire)\b",
            re.IGNORECASE,
        ),
        "Hinglish: KYC update / expiry pressure",
        24,
    ),

    (
        re.compile(
            r"\b(inaam|lottery|prize)\s*(jeeta|mila|jeetne)\b",
            re.IGNORECASE,
        ),
        "Hinglish: fake prize / lottery claim",
        24,
    ),

    # Telugu
    (
        re.compile(
            r"ఖాతా.{0,20}"
            r"(నిలిపివేయ|బ్లాక్|మూసివేయ|సస్పెండ్)",
        ),
        "Telugu: account blocking / suspension pressure",
        22,
    ),

    (
        re.compile(
            r"(వెంటనే|ఇప్పుడే|తక్షణం).{0,15}"
            r"(ధృవీక|క్లిక్|నిర్ధార)",
        ),
        "Telugu: immediate verification / click pressure",
        22,
    ),

    (
        re.compile(
            r"(ఓటీపీ|ఒటిపి|వన్\s*టైమ్\s*పాస్‌వర్డ్).{0,30}"
            r"(పంప|చెప్ప|షేర్|ఇవ్వ|నమోదు)",
        ),
        "Telugu: asks for OTP",
        35,
    ),

    (
        re.compile(
            r"(బహుమతి|లాటరీ|ప్రైజ్).{0,20}"
            r"(గెలిచ|వచ్చ|పొంద)",
        ),
        "Telugu: prize / lottery bait",
        24,
    ),

    (
        re.compile(
            r"(కేవైసీ|కెవైసి).{0,30}"
            r"(అప్డేట్|ధృవీక|ముగిస|బ్లాక్)",
        ),
        "Telugu: KYC pressure",
        24,
    ),

    # Tamil
    (
        re.compile(
            r"கணக்கு.{0,20}"
            r"(முடக்க|தடு|நிறுத்த|சஸ்பெண்ட்)",
        ),
        "Tamil: account blocking / suspension pressure",
        22,
    ),

    (
        re.compile(
            r"(இப்போது|உடனே|அவசரமாக).{0,15}"
            r"(சரிபார்|கிளிக்|உறுதிப்படுத்து)",
        ),
        "Tamil: immediate verification / click pressure",
        22,
    ),

    (
        re.compile(
            r"(ஓடிபி|OTP|ஒருமுறை\s*கடவுச்சொல்).{0,30}"
            r"(அனுப்பு|பகிர்|சொல்|உள்ளிடு|கொடு)",
            re.IGNORECASE,
        ),
        "Tamil: asks for OTP",
        35,
    ),

    (
        re.compile(
            r"(பரிசு|லாட்டரி).{0,20}"
            r"(வெற்றி|கிடைத்தது|வென்ற)",
        ),
        "Tamil: prize / lottery bait",
        24,
    ),

    (
        re.compile(
            r"(கேஒய்சி|KYC).{0,30}"
            r"(புதுப்பி|சரிபார்|காலாவதி|முடக்கு)",
            re.IGNORECASE,
        ),
        "Tamil: KYC pressure",
        24,
    ),
]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def clamp_score(value: float) -> int:
    return max(0, min(MAX_SCORE, int(round(value))))


def normalize_text(text: str) -> str:
    if not text:
        return ""

    text = str(text)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)

    return text.strip()


def get_risk_level(score: int) -> str:
    if score >= HIGH_RISK_THRESHOLD:
        return "high"

    if score >= MEDIUM_RISK_THRESHOLD:
        return "medium"

    return "low"


def make_reason(text: str) -> dict:
    return {
        "icon": "⚠️",
        "text": text,
    }


# ============================================================================
# URL EXTRACTION
# ============================================================================

def extract_urls(text: str) -> list[str]:

    if not text:
        return []

    found = URL_RE.findall(text)

    seen = set()
    output = []

    for url in found:

        clean_url = url.rstrip(".,!?;:)]}")

        if not clean_url:
            continue

        if "." not in clean_url:
            continue

        key = clean_url.lower()

        if key not in seen:
            seen.add(key)
            output.append(clean_url)

    return output


# ============================================================================
# URL ANALYSIS
# ============================================================================

def analyze_url(raw_url: str) -> dict:

    reasons = []
    score = 0

    if not raw_url:
        return {
            "score": 0,
            "reasons": [],
            "host": "",
        }

    url = str(raw_url).strip()

    # ---------------------------------------------------------
    # Parse URL
    # ---------------------------------------------------------

    has_scheme = bool(
        re.match(r"^https?://", url, re.IGNORECASE)
    )

    test_url = url if has_scheme else "http://" + url

    try:

        parsed = urlparse(test_url)

        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""

    except Exception:

        host = ""
        path = ""
        query = ""

    # ---------------------------------------------------------
    # HTTPS
    # ---------------------------------------------------------

    if not re.match(r"^https://", url, re.IGNORECASE):

        score += 8

        reasons.append(
            "Link does not use secure HTTPS"
        )

    # ---------------------------------------------------------
    # Invalid host
    # ---------------------------------------------------------

    if not host:

        score += 20

        reasons.append(
            "URL has an invalid or missing domain"
        )

        return {
            "score": clamp_score(score),
            "reasons": reasons[:MAX_REASONS],
            "host": "",
        }

    parts = host.split(".")

    # ---------------------------------------------------------
    # Raw IP
    # ---------------------------------------------------------

    if IP_HOST_RE.match(host):

        score += 30

        reasons.append(
            "Link uses a raw IP address instead of a domain name"
        )

    # ---------------------------------------------------------
    # @ symbol
    # ---------------------------------------------------------

    if "@" in url:

        score += 24

        reasons.append(
            "Link contains '@', which can hide the real destination"
        )

    # ---------------------------------------------------------
    # URL shortener
    # ---------------------------------------------------------

    if (
        host in SHORTENERS
        or any(host.endswith("." + domain) for domain in SHORTENERS)
    ):

        score += 18

        reasons.append(
            "Uses a URL shortener, which hides the final destination"
        )

    # ---------------------------------------------------------
    # Suspicious TLD
    # ---------------------------------------------------------

    if len(parts) >= 2:

        tld = parts[-1].lower()

        if tld in SUSPICIOUS_TLDS:

            score += 18

            reasons.append(
                f"Domain uses an unusual extension (.{tld}) "
                "often seen in scam links"
            )

    # ---------------------------------------------------------
    # Multiple hyphens
    # ---------------------------------------------------------

    hyphen_count = host.count("-")

    if hyphen_count >= 2:

        score += 12

        reasons.append(
            "Domain contains multiple hyphens, a common "
            "look-alike or deceptive-domain pattern"
        )

    elif hyphen_count == 1:

        score += 5

        reasons.append(
            "Domain contains a hyphen"
        )

    # ---------------------------------------------------------
    # Excessive subdomains
    # ---------------------------------------------------------

    if len(parts) >= 4:

        score += 10

        reasons.append(
            "Domain contains multiple subdomain levels"
        )

    # ---------------------------------------------------------
    # Suspicious words in domain
    # ---------------------------------------------------------

    domain_text = host.replace("-", " ")

    login_words = {
        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "security",
        "account",
        "banking",
        "update",
        "kyc",
    }

    found_login_words = [
        word
        for word in login_words
        if re.search(
            r"\b" + re.escape(word) + r"\b",
            domain_text,
            re.IGNORECASE,
        )
    ]

    if found_login_words:

        score += 15

        reasons.append(
            "Domain contains login/security-related wording: "
            + ", ".join(found_login_words)
        )

    # ---------------------------------------------------------
    # Brand impersonation
    # ---------------------------------------------------------

    detected_brand = None

    for brand in OFFICIAL_BRAND_DOMAINS:

        if re.search(
            r"\b" + re.escape(brand) + r"\b",
            domain_text,
            re.IGNORECASE,
        ):

            detected_brand = brand

            official_domains = OFFICIAL_BRAND_DOMAINS[brand]

            is_official = any(
                host == official
                or host.endswith("." + official)
                for official in official_domains
            )

            if not is_official:

                score += 35

                reasons.append(
                    f"Possible {brand.upper()} brand impersonation — "
                    "brand name appears in a non-official domain"
                )

            break

    # ---------------------------------------------------------
    # Brand + login combination
    # ---------------------------------------------------------

    if detected_brand and found_login_words:

        score += 20

        reasons.append(
            "Bank/brand name is combined with login or security wording"
        )

    # ---------------------------------------------------------
    # Suspicious path
    # ---------------------------------------------------------

    if SUSPICIOUS_PATH_RE.search(path):

        score += 12

        reasons.append(
            "URL path contains login, verification, payment, "
            "or account-security wording"
        )

    # ---------------------------------------------------------
    # Suspicious query parameters
    # ---------------------------------------------------------

    if query:

        query_lower = query.lower()

        sensitive_words = [
            "otp",
            "password",
            "pin",
            "cvv",
            "login",
            "verify",
            "account",
            "bank",
            "payment",
        ]

        found_query_words = [
            word
            for word in sensitive_words
            if word in query_lower
        ]

        if found_query_words:

            score += 12

            reasons.append(
                "URL parameters contain sensitive/security-related terms"
            )

    # ---------------------------------------------------------
    # Very long URL
    # ---------------------------------------------------------

    if len(url) > 150:

        score += 8

        reasons.append(
            "Unusually long URL"
        )

    # ---------------------------------------------------------
    # Repeated suspicious separators
    # ---------------------------------------------------------

    if host.count(".") >= 4:

        score += 8

        reasons.append(
            "Domain structure is unusually complex"
        )

    # ---------------------------------------------------------
    # Final score
    # ---------------------------------------------------------

    score = clamp_score(score)

    return {
        "score": score,
        "reasons": reasons[:MAX_REASONS],
        "host": host,
    }


# ============================================================================
# TEXT ANALYSIS
# ============================================================================

def analyze_text(text: str) -> dict:

    text = normalize_text(text)

    score = 0
    reasons = []

    # ---------------------------------------------------------
    # Empty input
    # ---------------------------------------------------------

    if not text:

        return {
            "score": 0,
            "level": "low",
            "reasons": [
                make_reason("No text was provided")
            ],
            "urls_found": [],
            "action": {
                "title": "No content to analyze",
                "text": "Provide a message, URL, screenshot, or QR code.",
            },
        }

    # ---------------------------------------------------------
    # Text pattern analysis
    # ---------------------------------------------------------

    for pattern, reason, weight in TEXT_PATTERNS:

        if pattern.search(text):

            score += weight

            reasons.append(reason)

            if len(reasons) >= MAX_REASONS:
                break

    # ---------------------------------------------------------
    # Brand mentions
    # ---------------------------------------------------------

    brand_matches = BRAND_RE.findall(text)

    if brand_matches:

        unique_brands = []

        for brand in brand_matches:

            brand_lower = brand.lower()

            if brand_lower not in unique_brands:
                unique_brands.append(brand_lower)

        if not any(
            "brand" in reason.lower()
            for reason in reasons
        ):

            score += 8

            reasons.append(
                "Message mentions a financial or major online brand"
            )

    # ---------------------------------------------------------
    # URL analysis
    # ---------------------------------------------------------

    urls = extract_urls(text)

    for url in urls:

        url_result = analyze_url(url)

        score += url_result["score"]

        for reason in url_result["reasons"]:

            if reason not in reasons:
                reasons.append(reason)

            if len(reasons) >= MAX_REASONS:
                break

        if len(reasons) >= MAX_REASONS:
            break

    # ---------------------------------------------------------
    # Excessive punctuation
    # ---------------------------------------------------------

    exclamation_count = text.count("!")

    if exclamation_count >= 4:

        score += 8

        if len(reasons) < MAX_REASONS:

            reasons.append(
                "Excessive exclamation marks / pressure formatting"
            )

    # ---------------------------------------------------------
    # All caps
    # ---------------------------------------------------------

    letters = re.findall(r"[A-Za-z]", text)

    if len(letters) >= 20:

        uppercase_letters = sum(
            1 for char in letters if char.isupper()
        )

        uppercase_ratio = uppercase_letters / len(letters)

        if uppercase_ratio >= 0.75:

            score += 6

            if len(reasons) < MAX_REASONS:

                reasons.append(
                    "Unusually high use of capital letters"
                )

    # ---------------------------------------------------------
    # Final score
    # ---------------------------------------------------------

    score = clamp_score(score)

    level = get_risk_level(score)

    # ---------------------------------------------------------
    # Default reason
    # ---------------------------------------------------------

    if not reasons:

        reasons.append(
            "No known phishing indicators, urgency language, "
            "or suspicious links detected"
        )

    # ---------------------------------------------------------
    # Action message
    # ---------------------------------------------------------

    if level == "high":

        action = {
            "title": "High risk — do not interact with this content.",
            "text": (
                "Strong phishing indicators were detected. "
                "Do not enter OTP, PIN, CVV, passwords, "
                "or banking credentials."
            ),
        }

    elif level == "medium":

        action = {
            "title": "Suspicious content — verify before proceeding.",
            "text": (
                "Several warning signs were detected. "
                "Do not share sensitive information until "
                "the sender and destination are verified."
            ),
        }

    else:

        action = {
            "title": "No strong warning signs found — stay alert anyway.",
            "text": (
                "This engine found no major red flags, "
                "but no automated check is perfect. "
                "Never share OTP, PIN, CVV, passwords, "
                "or banking credentials based only on "
                "an unsolicited message."
            ),
        }

    # ---------------------------------------------------------
    # Stable response structure
    # ---------------------------------------------------------

    return {
        "score": score,
        "level": level,
        "reasons": [
            make_reason(reason)
            for reason in reasons[:MAX_REASONS]
        ],
        "urls_found": urls,
        "action": action,
    }


# ============================================================================
# OPTIONAL ALIASES
# ============================================================================

def analyze_message(text: str) -> dict:
    """
    Alias for analyze_text().
    """
    return analyze_text(text)


# ============================================================================
# TEST
# ============================================================================

if __name__ == "__main__":

    test_url = "https://secure-sbi-login.example.com"

    print("=" * 70)
    print("LinguaShield AI — Phishing Engine Test")
    print("=" * 70)

    print("\nTesting URL:")
    print(test_url)

    result = analyze_url(test_url)

    print("\nURL RESULT:")
    print(result)

    print("\nTesting text:")

    message = (
        "Your SBI account will be blocked. "
        "Verify your account now using "
        "https://secure-sbi-login.example.com"
    )

    result = analyze_text(message)

    print(result)

    print("\nDone.")