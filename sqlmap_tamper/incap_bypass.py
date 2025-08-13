#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
incap_combo: Rotasi nilai cookie Incapsula tiap request + selipkan token palsu.
- Ganti value untuk setiap kunci cookie yang match "incap_ses_*"
- Tambahkan "bypass_token=<random>" di akhir cookie jika belum ada
Author: jago shell
"""

import re
import random
import string
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

_RE_INCAP_SES = re.compile(r"(?i)\b(incap_ses_[^=\s]*)=([^;]*)")
_BYPASS_KEY = "bypass_token"

def _rand_token(length=48):
    # Mirip base64 charset biar terlihat wajar
    chars = string.ascii_letters + string.digits + "+/"
    return ''.join(random.choice(chars) for _ in range(length))

def dependencies():
    pass

def tamper(payload, **kwargs):
    headers = kwargs.get("headers", {})
    cookie = headers.get("Cookie", "")

    if cookie:
        # Rotasi semua pasangan cookie yang namanya match "incap_ses_*"
        def _repl(m):
            name = m.group(1)
            return f"{name}={_rand_token()}"
        cookie = _RE_INCAP_SES.sub(_repl, cookie)

        # Sisipkan token palsu jika belum ada
        if _BYPASS_KEY.lower() not in cookie.lower():
            if cookie.strip().endswith(";"):
                cookie = cookie + f" {_BYPASS_KEY}={_rand_token(12)}"
            else:
                cookie = cookie + f"; {_BYPASS_KEY}={_rand_token(12)}"

        headers["Cookie"] = cookie

    return payload
