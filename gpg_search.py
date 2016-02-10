#!/usr/bin/env python
# -*- coding: utf-8; -*-

"""Search encrypted mails in common mailbox formats."""

# Copyright (C)  2016 Johannes Dillmann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function

import mailbox
import os.path
import re
import warnings
from email.header import decode_header
from email.parser import Parser

import bs4
import gnupg
import six

_gpg = gnupg.GPG()
_parser = Parser()
_re_begin_pgp = re.compile('^\s*-----BEGIN PGP MESSAGE-----')
_default_charset = "utf-8"


def _def(value, default):
    return default if value is None else value


def decrypt(encrypted, charset_hint=None):
    decrypted = _gpg.decrypt(encrypted)
    m = _parser.parsestr(str(decrypted))
    return get_body(m, charset_hint)


def decrypt_inline(text, charset_hint=None):
    if _re_begin_pgp.match(text):
        return decrypt(text, charset_hint)
    return text


def decode(m, charset_hint=None):
    charset = m.get_content_charset()
    if charset is None:
        charset = _def(charset_hint, _default_charset)

    # or decode(charset, errors="replace")
    body = m.get_payload(decode=True).decode(charset)
    return body, charset


def get_body(m, charset_hint=None):
    if m.get_content_type() == "text/plain":
        body, charset = decode(m, charset_hint)
        body = decrypt_inline(body, charset)
        return body

    elif m.get_content_type() == "text/html":
        html, charset = decode(m, charset_hint)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            soup = bs4.BeautifulSoup(html)

        body = soup.get_text()
        body = decrypt_inline(body, charset)
        return body

    elif m.get_content_type() == "multipart/encrypted":
        payloads = m.get_payload()
        if payloads[0].get_content_type() == "application/pgp-encrypted":
            encrypted = payloads[1].get_payload()
            return decrypt(encrypted)

    elif m.get_content_type() == "multipart/signed":
        return get_body(m.get_payload(i=0))

    elif m.get_content_type() == "multipart/mixed":
        for payload in m.get_payload():
            if payload.get_content_type() == "text/plain":
                return get_body(payload)
            elif payload.get_content_type() == "multipart/alternative":
                return get_body(payload)

    elif m.get_content_type() == "multipart/alternative":
        found = None
        for payload in m.get_payload():
            if payload.get_content_type() == "text/plain":
                found = payload
                break
            elif payload.get_content_type() == "text/html":
                found = payload
                # continue looking for text/plain
        return get_body(found)


def get_headers(m):
    return dict([(key, _decode_header(m[key]))
                 for key in ["from",  "to", "date", "subject"]])


def _decode_header(header):
    parts = decode_header(header)
    return " ".join(map(_decode_if_bytes, parts))


def _decode_if_bytes(header):
    part, charset = header
    if type(part) == six.binary_type:
        charset = _def(charset, _default_charset)
        return part.decode(charset)
    return six.u(part)


def search(mbox, query):
    query_parts = map(re.escape, query.split(" "))
    re_query = re.compile("[\W_]+".join(query_parts), re.I)

    result = ((m, body, match) for m, body, match in
              ((m, body, re_query.search(body)) for m, body in
               ((m, get_body(m)) for m in mbox)
               if body is not None)
              if match is not None)
    return result


def print_results(r):
    had_results = False

    for m, body, match in r:
        had_results = True
        headers = get_headers(m)

        print("=" * 80)
        print(u""
              "Date:    {date}\n"
              "From:    {from}\n"
              "To:      {to}\n"
              "Subject: {subject}"
              .format(**headers))
        print("-" * 80)
        print(body[:match.start()].lstrip(),
              "\033[0;33m",   # ANSI YELLOW
              body[match.start():match.end()],
              "\033[0m",
              body[match.end():].rstrip() if match.end() < len(body) else "",
              sep=""
              )
        print("\n")

    return had_results


def _check_mailbox_exists(value):
    mailbox = str(value)
    if not os.path.exists(mailbox):
        raise argparse.ArgumentTypeError("%s is no valid path" % value)
    return mailbox


if __name__ == '__main__':
    import argparse

    mailboxfmts = {
        "mbox": mailbox.mbox,
        "maildir": mailbox.Maildir,
        "mh": mailbox.MH,
        "babyl": mailbox.Babyl,
        "mmdf": mailbox.MMDF
    }

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mailbox", type=_check_mailbox_exists,
                        help="Path to the mailbox file or directory")
    parser.add_argument("query", nargs="+",
                        help="Query (terms) to search for in mails")
    parser.add_argument("--type", choices=mailboxfmts.keys(), default="mbox",
                        help="Type of the mailbox. See also: "
                             "https://docs.python.org/3/library/mailbox.html"
                        )

    args = parser.parse_args()

    box = mailboxfmts[args.type](args.mailbox, create=False)

    query = " ".join(args.query)
    result = search(box, query)
    had_results = print_results(result)

    if not had_results:
        print("nothing found")
