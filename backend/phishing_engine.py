"""
LinguaShield AI — Phishing Detection Engine
============================================

Rule-based multilingual phishing detection engine.

Supported:
    - English
    - Hindi (Devanagari)
    - Hinglish
    - Telugu
    - Tamil

Detection:
    - Urgency / pressure
    - OTP / PIN / CVV requests
    - KYC scams
    - Prize / lottery scams
    - Fake legal / police threats
    - Fake job / easy-money offers
    - Refund scams
    - Account blocking threats
    - Brand impersonation
    - Suspicious URLs
    - URL shorteners
    - Raw IP addresses
    - Suspicious TLDs
    - Excessive subdomains
    - Look-alike domains
    - Excessive punctuation

The returned structure is intentionally stable so that the
FastAPI layer and React frontend do not need to change.

Main functions:
    analyze_text(text)
    analyze_url(url)
    extract_urls(text)
"""

import re
from urllib.parse import urlparse


# ============================================================================
# CONFIGURATION
# ============================================================================

MAX_SCORE = 100
MAX_REASONS = 7

# Risk thresholds
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

# URL extractor.
# Handles:
#   https://example.com
#   http://example.com/path
#   www.example.com
#   example.com/login
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

# Common suspicious URL path words
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
# TEXT PATTERNS
#
# Format:
#   (compiled_regex, reason, weight)
# ============================================================================

URGENCY_PATTERNS = [

    # ------------------------------------------------------------------------
    # ENGLISH — URGENCY
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # OTP / PIN / CVV
    #
    # Detects BOTH:
    #
    #   "share your OTP"
    #   "OTP share karo"
    #   "enter OTP"
    #   "send your PIN"
    #
    # But does NOT flag:
    #
    #   "Never share your OTP"
    #
    # because the request/action relationship is checked.
    # ------------------------------------------------------------------------

    (
        re.compile(
            r"(?:"
            r"\b(otp|one\s*time\s*password|cvv|"
            r"pin|pin\s*number|upi\s*pin|"
            r"net\s*banking\s*password)\b"
            r".{0,35}"
            r"\b(share|enter|provide|send|tell|give|submit|"
            r"confirm|forward)\b"
            r"|"
            r"\b(share|enter|provide|send|tell|give|submit|"
            r"confirm|forward)\b"
            r".{0,35}"
            r"\b(otp|one\s*time\s*password|cvv|"
            r"pin|pin\s*number|upi\s*pin|"
            r"net\s*banking\s*password)\b"
            r")",
            re.IGNORECASE,
        ),
        "Asks you to share OTP/PIN/CVV — legitimate banks do not ask for these",
        35,
    ),

    # ------------------------------------------------------------------------
    # KYC
    # ------------------------------------------------------------------------

    (
        re.compile(
            r"\bkyc\b.{0,40}"
            r"\b(update|verify|expire|expired|expiring|"
            r"suspend|blocked|complete|required|pending)\b",
            re.IGNORECASE,
        ),
        "KYC update/expiry pressure — a common scam script",
        24,
    ),

    (
        re.compile(
            r"\b("
            r"know\s*your\s*customer"
            r")\b.{0,40}"
            r"\b(update|verify|expire|suspend|complete|required)\b",
            re.IGNORECASE,
        ),
        "KYC verification pressure",
        22,
    ),

    # ------------------------------------------------------------------------
    # PRIZE / LOTTERY / REWARD
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # LEGAL / POLICE / DIGITAL ARREST
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # JOB / EASY MONEY
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # REFUND / PAYMENT
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # ACCOUNT SECURITY
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # PASSWORD / LOGIN
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # HINDI — DEVANAGARI
    # ------------------------------------------------------------------------

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

    (
        re.compile(
            r"(केवाईसी|के\s*वाई\s*सी).{0,30}"
            r"(अपडेट|सत्यापित|समाप्त|बंद|ब्लॉक)",
        ),
        "Hindi: KYC pressure",
        24,
    ),

    # ------------------------------------------------------------------------
    # HINGLISH
    # ------------------------------------------------------------------------

    (
        re.compile(
            r"\b("
            r"aapka|apka"
            r")\s*(account|khata)\s*"
            r"(block|band|suspend|blocked)\s*"
            r"(ho\s*jayega|hoga)?\b",
            re.IGNORECASE,
        ),
        "Hinglish: your account may be blocked",
        22,
    ),

    (
        re.compile(
            r"\b("
            r"abhi|turant|jaldi"
            r")\s*"
            r"(verify|click|update|confirm)\s*"
            r"(karo|kare|karein|karna)?\b",
            re.IGNORECASE,
        ),
        "Hinglish: immediate verification / click pressure",
        22,
    ),

    (
        re.compile(
            r"\b("
            r"apna|aapna"
            r")\s*"
            r"(otp|pin|password|cvv)\s*"
            r"(bhejo|send\s*karo|share\s*karo|batao|do)\b",
            re.IGNORECASE,
        ),
        "Hinglish: asks you to share OTP/PIN/password",
        35,
    ),

    (
        re.compile(
            r"\b("
            r"kyc\s*(update|karo|karein|karna)|"
            r"kyc\s*expire"
            r")\b",
            re.IGNORECASE,
        ),
        "Hinglish: KYC update / expiry pressure",
        24,
    ),

    (
        re.compile(
            r"\b("
            r"inaam|lottery|prize"
            r")\s*"
            r"(jeeta|mila|jeetne)\b",
            re.IGNORECASE,
        ),
        "Hinglish: fake prize / lottery claim",
        24,
    ),

    # ------------------------------------------------------------------------
    # TELUGU
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # TAMIL
    # ------------------------------------------------------------------------

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
    """
    Keep score between 0 and 100.
    """
    return max(0, min(MAX_SCORE, int(round(value))))


def normalize_text(text: str) -> str:
    """
    Normalize whitespace while preserving Unicode characters.
    """
    if not text:
        return ""

    text = str(text)

    # Normalize repeated whitespace
    text = re.sub(r"[ \t\r\f\v]+", " ", text)

    return text.strip()


def get_risk_level(score: int) -> str:
    """
    Convert numeric score into risk level.
    """
    if score >= HIGH_RISK_THRESHOLD:
        return "high"

    if score >= MEDIUM_RISK_THRESHOLD:
        return "medium"

    return "low"


# ============================================================================
# URL EXTRACTION
# ============================================================================

def extract_urls(text: str) -> list[str]:
    """
    Extract unique URLs/domains from text.

    Examples:
        https://example.com
        http://example.com/login
        www.example.com
        example.com/login
    """

    if not text:
        return []

    found = URL_RE.findall(text)

    seen = set()
    output = []

    for url in found:
        # Remove common sentence punctuation
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
    """
    Analyze a URL using heuristic rules.

    Returns:

    {
        "score": int,
        "reasons": list[str],
        "host": str
    }
    """

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
    # Invalid / missing host
    # ---------------------------------------------------------

    if not host:
        score += 20
        reasons.append(
            "URL has an invalid or missing domain"
        )

        return {
            "score": clamp_score(score),
            "reasons": reasons,
            "host": "",
        }

    # ---------------------------------------------------------
    # Raw IP address
    # ---------------------------------------------------------

    if IP_HOST_RE.match(host):
        score += 30

        reasons.append(
            "Link uses a raw IP address instead of a domain name — "
            "a strong phishing signal"
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

    if host in SHORTENERS or any(
        host.endswith("." + domain)
        for domain in SHORTENERS
    ):
        score += 18

        reasons.append(
            "Uses a URL shortener, which hides the final destination"
        )

    # ---------------------------------------------------------
    # Suspicious TLD
    # ---------------------------------------------------------

    parts = host.split(".")

    if len(parts) >= 2:

        tld = parts[-1].lower()

        if tld in SUSPICIOUS_TLDS:
            score += 18

            reasons.append(
                f"Domain uses an unusual extension (.{tld}) "
                f"often seen in scam links"
            )

    # ---------------------------------------------------------
    # Multiple hyphens
    # ---------------------------------------------------------

    hyphen_count = host.count("-")

    if hyphen_count >= 2:
        score += 12

        reasons.append(
            "Domain contains multiple hyphens, common in "
            "look-alike or deceptive domains"
        )

    # ---------------------------------------------------------
    # Very long hostname
    # ---------------------------------------------------------

    if len(host) > 35:
        score += 8

        reasons.append(
            "Unusually long domain name"
        )

    # ---------------------------------------------------------
    # Excessive subdomains
    # ---------------------------------------------------------

    subdomain_count = max(host.count(".") - 1, 0)

    if subdomain_count >= 3:
        score += 12

        reasons.append(
            "Unusually long chain of subdomains can disguise "
            "the real destination"
        )

    # ---------------------------------------------------------
    # Suspicious path
    # ---------------------------------------------------------

    if SUSPICIOUS_PATH_RE.search(path):

        # Only add a small amount because legitimate sites
        # also have login / verify pages.
        score += 6

        reasons.append(
            "URL contains a sensitive action such as login, "
            "verification, KYC, payment, or account update"
        )

    # ---------------------------------------------------------
    # Suspicious query parameters
    # ---------------------------------------------------------

    if query:

        if re.search(
            r"\b(otp|password|pin|cvv|verify|token|login)\b",
            query,
            re.IGNORECASE,
        ):
            score += 10

            reasons.append(
                "URL query contains sensitive authentication terms"
            )

    # ---------------------------------------------------------
    # Brand impersonation
    # ---------------------------------------------------------

    brand_match = BRAND_RE.search(host)

    if brand_match:

        brand = (
            brand_match.group(0)
            .lower()
            .replace(" ", "")
        )

        # Known legitimate domain endings.
        legitimate_domains = {
            "sbi.co.in",
            "hdfcbank.com",
            "icicibank.com",
            "axisbank.com",
            "paytm.com",
            "phonepe.com",
            "google.com",
            "amazon.in",
            "amazon.com",
            "flipkart.com",
            "microsoft.com",
            "apple.com",
            "whatsapp.com",
            "instagram.com",
            "facebook.com",
            "rbi.org.in",
            "incometax.gov.in",
        }

        is_legitimate = any(
            host == domain or host.endswith("." + domain)
            for domain in legitimate_domains
        )

        if not is_legitimate:

            # Avoid penalizing generic domains too aggressively.
            registrable = ""

            if len(parts) >= 2:
                registrable = parts[-2].lower()

            if brand not in registrable:

                score += 26

                reasons.append(
                    f"Domain mentions '{brand_match.group(0).upper()}' "
                    f"but does not appear to be the official domain"
                )

    # ---------------------------------------------------------
    # Suspicious domain keywords
    # ---------------------------------------------------------

    suspicious_domain_words = [
        "verify",
        "secure-login",
        "account-verify",
        "kyc-update",
        "bank-login",
        "wallet-verify",
        "claim-reward",
        "otp-verify",
    ]

    lower_host = host.lower()

    matched_suspicious_words = [
        word
        for word in suspicious_domain_words
        if word in lower_host
    ]

    if matched_suspicious_words:

        score += 12

        reasons.append(
            "Domain contains suspicious verification/account "
            "keywords"
        )

    return {
        "score": clamp_score(score),
        "reasons": reasons,
        "host": host,
    }


# ============================================================================
# CONTEXTUAL FALSE-POSITIVE PROTECTION
# ============================================================================

def is_safe_otp_warning(text: str) -> bool:
    """
    Detect educational/safety messages such as:

        Never share your OTP.
        Do not share OTP.
        Banks never ask for OTP.

    These should not receive the full OTP-request penalty.
    """

    if not text:
        return False

    safe_patterns = [
        r"\bnever\s+share\b.{0,20}\b(otp|pin|cvv)\b",
        r"\bdo\s+not\s+share\b.{0,20}\b(otp|pin|cvv)\b",
        r"\bdon't\s+share\b.{0,20}\b(otp|pin|cvv)\b",
        r"\bnever\s+give\b.{0,20}\b(otp|pin|cvv)\b",
        r"\bbanks?\s+(?:never|do\s+not|don't)\s+ask\b.{0,20}\b(otp|pin|cvv)\b",
    ]

    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in safe_patterns
    )


# ============================================================================
# ACTION MESSAGES
# ============================================================================

ACTIONS = {
    "high": {
        "title": "Don't click, reply, or share any details.",
        "text": (
            "This message shows strong phishing signals. "
            "Do not open the link, do not share OTP/PIN/CVV, "
            "and do not call any number provided in the message. "
            "Verify directly through the organisation's official "
            "app or website."
        ),
    },

    "medium": {
        "title": "Pause and verify independently.",
        "text": (
            "Some signals here look suspicious but are not "
            "conclusive. Do not act on the message directly. "
            "Open the official app or type the organisation's "
            "website yourself and verify the information."
        ),
    },

    "low": {
        "title": "No strong warning signs found — stay alert anyway.",
        "text": (
            "This engine found no major red flags, but no "
            "automated check is perfect. Never share OTP, PIN, "
            "CVV, passwords, or banking credentials based only "
            "on an unsolicited message."
        ),
    },
}


# ============================================================================
# MAIN TEXT ANALYZER
# ============================================================================

def analyze_text(raw_text: str) -> dict:
    """
    Analyze a complete message.

    Returns:

    {
        "score": 0-100,
        "level": "low" | "medium" | "high",
        "reasons": [
            {
                "icon": "🧩",
                "text": "..."
            }
        ],
        "urls_found": [],
        "action": {
            "title": "...",
            "text": "..."
        }
    }
    """

    text = normalize_text(raw_text)

    score = 0
    reasons = []

    # ---------------------------------------------------------
    # Empty message
    # ---------------------------------------------------------

    if not text:

        return {
            "score": 0,
            "level": "low",
            "reasons": [
                {
                    "icon": "ℹ️",
                    "text": "No message content was provided",
                }
            ],
            "urls_found": [],
            "action": ACTIONS["low"],
        }

    # ---------------------------------------------------------
    # Safe OTP warning protection
    # ---------------------------------------------------------

    safe_otp_warning = is_safe_otp_warning(text)

    # ---------------------------------------------------------
    # Text indicator scan
    # ---------------------------------------------------------

    for pattern, label, weight in URGENCY_PATTERNS:

        try:
            matched = pattern.search(text)
        except Exception:
            matched = False

        if matched:

            # If this is clearly an educational warning,
            # don't count an OTP request as dangerous.
            if (
                safe_otp_warning
                and "OTP" in label.upper()
            ):
                continue

            score += weight

            reasons.append(
                {
                    "icon": "🧩",
                    "text": label,
                }
            )

    # ---------------------------------------------------------
    # URL analysis
    # ---------------------------------------------------------

    urls = extract_urls(text)

    for url in urls:

        url_result = analyze_url(url)

        # URL scores contribute 60%.
        #
        # Example:
        # URL score 30 → contributes 18.
        #
        # This prevents URL heuristics from dominating
        # the message analysis.
        score += url_result["score"] * 0.60

        host = url_result.get("host", "")

        for reason_text in url_result.get("reasons", []):

            suffix = f" ({host})" if host else ""

            reasons.append(
                {
                    "icon": "🔗",
                    "text": reason_text + suffix,
                }
            )

    # ---------------------------------------------------------
    # Excessive exclamation marks
    # ---------------------------------------------------------

    exclamation_count = text.count("!")

    if exclamation_count >= 3:

        score += 7

        reasons.append(
            {
                "icon": "❗",
                "text": "Excessive urgency punctuation",
            }
        )

    # ---------------------------------------------------------
    # ALL CAPS pressure
    # ---------------------------------------------------------

    words = re.findall(r"\b[A-Z]{4,}\b", text)

    if len(words) >= 4:

        score += 5

        reasons.append(
            {
                "icon": "⚠️",
                "text": "Excessive use of capitalized words",
            }
        )

    # ---------------------------------------------------------
    # Final score
    # ---------------------------------------------------------

    score = clamp_score(score)

    level = get_risk_level(score)

    # ---------------------------------------------------------
    # No reasons found
    # ---------------------------------------------------------

    if not reasons:

        reasons.append(
            {
                "icon": "✅",
                "text": (
                    "No known phishing indicators, urgency "
                    "language, or suspicious links detected"
                ),
            }
        )

    # ---------------------------------------------------------
    # Final response
    # ---------------------------------------------------------

    return {
        "score": score,
        "level": level,
        "reasons": reasons[:MAX_REASONS],
        "urls_found": urls,
        "action": ACTIONS[level],
    }


# ============================================================================
# OPTIONAL SIMPLE TEST
# ============================================================================

if __name__ == "__main__":

    test_messages = [
        "Your account will be blocked. Verify now and share your OTP.",

        "Congratulations! You won ₹50,000. Click here to claim your reward.",

        "Your KYC will expire today. Verify immediately.",

        "Never share your OTP with anyone.",

        "Hello, have a nice day.",

        "Your bank account is suspended. Login at http://example.xyz/verify",
    ]

    print("=" * 70)
    print("LinguaShield AI — Phishing Detection Engine")
    print("=" * 70)

    for number, message in enumerate(test_messages, start=1):

        result = analyze_text(message)

        print()
        print(f"TEST {number}")
        print("-" * 70)
        print("Message :", message)
        print("Score   :", result["score"])
        print("Level   :", result["level"])
        print("URLs    :", result["urls_found"])

        print("Reasons:")

        for reason in result["reasons"]:
            print(
                f"  {reason['icon']} {reason['text']}"
            )

        print("Action:")
        print(
            f"  {result['action']['title']}"
        )