[![GitHub release](https://img.shields.io/github/release/PurpleI2P/i2pd.svg?label=latest%20release)](https://github.com/PurpleI2P/i2pd/releases/latest)
[![Snapcraft release](https://snapcraft.io/i2pd/badge.svg)](https://snapcraft.io/i2pd)
[![License](https://img.shields.io/github/license/PurpleI2P/i2pd.svg)](https://github.com/PurpleI2P/i2pd/blob/openssl/LICENSE)
[![Packaging status](https://repology.org/badge/tiny-repos/i2pd.svg)](https://repology.org/project/i2pd/versions)
[![Docker Pulls](https://img.shields.io/docker/pulls/purplei2p/i2pd)](https://hub.docker.com/r/purplei2p/i2pd)

*note: i2pd for Android can be found in [i2pd-android](https://github.com/PurpleI2P/i2pd-android) repository and with Qt GUI in [i2pd-qt](https://github.com/PurpleI2P/i2pd-qt) repository*

i2pd
====

[Русская версия](https://github.com/PurpleI2P/i2pd_docs_ru/blob/master/README.md)

i2pd (I2P Daemon) is a full-featured C++ implementation of I2P client.  

I2P (Invisible Internet Protocol) is a universal anonymous network layer.  
All communications over I2P are anonymous and end-to-end encrypted, participants
don't reveal their real IP addresses.  

I2P client is a software used for building and using anonymous I2P
networks. Such networks are commonly used for anonymous peer-to-peer
applications (filesharing, cryptocurrencies) and anonymous client-server
applications (websites, instant messengers, chat-servers).  

I2P allows people from all around the world to communicate and share information
without restrictions.  

Features
--------

* Distributed anonymous networking framework  
* End-to-end encrypted communications  
* Small footprint, simple dependencies, fast performance  
* Rich set of APIs for developers of secure applications  

Resources
---------

* [Website](http://i2pd.website)
* [Documentation](https://i2pd.readthedocs.io/en/latest/)
* [Wiki](https://github.com/PurpleI2P/i2pd/wiki)
* [Tickets/Issues](https://github.com/PurpleI2P/i2pd/issues)
* [Specifications](https://geti2p.net/spec)
* [Twitter](https://twitter.com/hashtag/i2pd)

Installing
----------

The easiest way to install i2pd is by using precompiled packages and binaries.
You can fetch most of them on [release](https://github.com/PurpleI2P/i2pd/releases/latest) page.  
Please see [documentation](https://i2pd.readthedocs.io/en/latest/user-guide/install/) for more info.

Building
--------
See [documentation](https://i2pd.readthedocs.io/en/latest/) for how to build
i2pd from source on your OS.  

note: i2pd with Qt GUI can be found in [i2pd-qt](https://github.com/PurpleI2P/i2pd-qt) repository and for android in [i2pd-android](https://github.com/PurpleI2P/i2pd-android) repository.


Build instructions:

* [unix](https://i2pd.readthedocs.io/en/latest/devs/building/unix/)
* [windows](https://i2pd.readthedocs.io/en/latest/devs/building/windows/)
* [iOS](https://i2pd.readthedocs.io/en/latest/devs/building/ios/)
* [android](https://i2pd.readthedocs.io/en/latest/devs/building/android/)


**Supported systems:**

* GNU/Linux - [![Build Status](https://travis-ci.org/PurpleI2P/i2pd.svg?branch=openssl)](https://travis-ci.org/PurpleI2P/i2pd)
  * CentOS / Fedora / Mageia - [![Build Status](https://copr.fedorainfracloud.org/coprs/supervillain/i2pd/package/i2pd-git/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/supervillain/i2pd/package/i2pd-git/)
  * Alpine, ArchLinux, openSUSE, Gentoo, Debian, Ubuntu, etc.
* Windows - [![Build status](https://ci.appveyor.com/api/projects/status/1908qe4p48ff1x23?svg=true)](https://ci.appveyor.com/project/PurpleI2P/i2pd)
* Mac OS X - [![Build Status](https://travis-ci.org/PurpleI2P/i2pd.svg?branch=openssl)](https://travis-ci.org/PurpleI2P/i2pd)
* Docker image - [![Build Status](https://img.shields.io/docker/cloud/build/purplei2p/i2pd)](https://hub.docker.com/r/purplei2p/i2pd/builds/)
* Snap
* FreeBSD
* Android
* iOS

Using i2pd
----------

See [documentation](https://i2pd.readthedocs.io/en/latest/user-guide/run/) and
[example config file](https://github.com/PurpleI2P/i2pd/blob/openssl/contrib/i2pd.conf).

Donations
---------

BTC: 3MDoGJW9TLMTCDGrR9bLgWXfm6sjmgy86f  
LTC: LKQirrYrDeTuAPnpYq5y7LVKtywfkkHi59  
ETH: 0x9e5bac70d20d1079ceaa111127f4fb3bccce379d  
DASH: Xw8YUrQpYzP9tZBmbjqxS3M97Q7v3vJKUF  
ZEC: t1cTckLuXsr1dwVrK4NDzfhehss4NvMadAJ  
GST: GbD2JSQHBHCKLa9WTHmigJRpyFgmBj4woG  

License
-------

This project is licensed under the BSD 3-clause license, which can be found in the file
LICENSE in the root of the project source code.  
