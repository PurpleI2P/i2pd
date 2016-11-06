Build requirements
==================

In general, for building i2pd you need several things:

* compiler with c++11 support (for example: gcc >= 4.7, clang)
* boost >= 1.49
* openssl library
* zlib library (openssl already depends on it)

Optional tools:

* cmake >= 2.8 (or 3.3+ if you want to use precompiled headers on windows)
* miniupnp library (for upnp support)
* [websocketpp](https://github.com/zaphoyd/websocketpp/) (for websocket ui)
