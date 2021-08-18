`xgettext` command for extracting translation
---

```
xgettext --omit-header -ctr: -ktr -ktr:1,2 daemon/HTTPServer.cpp libi2pd_client/HTTPProxy.cpp
```

Regex for transforming gettext translations to our format:
---

```
in:  msgid\ \"(.*)\"\nmsgid_plural\ \"(.*)\"\nmsgstr\[0\]\ \"(.*)\"\nmsgstr\[1\]\ \"(.*)\"\n(msgstr\[2\]\ \"(.*)\"\n)?(msgstr\[3\]\ \"(.*)\"\n)?(msgstr\[4\]\ \"(.*)\"\n)?(msgstr\[5\]\ \"(.*)\"\n)?
out: #{"$2", {"$3", "$4", "$6", "$8", "$10"}},\n
```

```
in:  msgid\ \"(.*)\"\nmsgstr\ \"(.*)\"\n
out: {"$1", "$2"},\n
```

```
in:  ^#[:.](.*)$\n
out: <to empty line>
```

```
in:  \n\n
out: \n
```
