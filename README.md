# gpg_search
Search encrypted mails in common mailbox formats.

```
usage: gpg_search.py [-h] [--type {mmdf,babyl,mh,mbox,maildir}]
                     mailbox query [query ...]

Search encrypted mails in common mailbox formats.

positional arguments:
  mailbox               Path to the mailbox file or directory
  query                 Query (terms) to search for in mails

optional arguments:
  -h, --help            show this help message and exit
  --type {mmdf,babyl,mh,mbox,maildir}
                        Type of the mailbox. See also:
                        https://docs.python.org/3/library/mailbox.html
```
