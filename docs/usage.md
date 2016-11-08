Usage and tutorials
===================


i2pd can be used for:

* [anonymous websites](#browsing-and-hosting-websites)
* [anonymous chats](#using-and-hosting-chat-servers)
* [anonymous file sharing](#file-sharing)

and many more.

## Starting, stopping and reloading configuration

After you have built i2pd from source, just run a binary:

    ./i2pd

To display all available options:

    ./i2pd --help

i2pd can be controlled with signals. Process ID by default is written to file `~/.i2pd/i2pd.pid` or `/var/run/i2pd/i2pd.pid`.
You can use `kill` utility to send signals like this:

    kill -TERM $( cat /var/run/i2pd/i2pd.pid )

i2pd supports the following signals:

    TERM - Graceful shutdown. i2pd will wait for 10 minutes and stop. Send second TERM signal to shutdown i2pd immediately.
    HUP - Reload configuration files.


### systemd unit

Some binary Linux packages have a systemd control unit, so it is possible to managage i2pd with it.

Start/stop i2pd:

    sudo systemctl start i2pd.service
    sudo systemctl stop i2pd.service

Enable/disable i2pd to be started on bootup:

    sudo systemctl enable i2pd.service
    sudo systemctl disable i2pd.service


## Configuring i2pd

See [configuration page](i2pd.readthedocs.io/page/configuration.html).


## Browsing and hosting websites

### Browse anonymous websites

To browse anonymous websites inside Invisible Internet, configure your web browser to use HTTP proxy 127.0.0.1:4444 (available by default in i2pd).

In Firefox: Preferences -> Advanced -> Network tab -> Connection Settings -> choose Manual proxy configuration, Enter HTTP proxy 127.0.0.1, Port 4444

In Chromium: run chromium executable with key

    chromium --proxy-server="http://127.0.0.1:4444"

Note that if you wish to stay anonymous too you'll need to tune your browser for better privacy. Do your own research, [can start here](http://www.howtogeek.com/102032/how-to-optimize-mozilla-firefox-for-maximum-privacy/).

Big list of Invisible Internet websites can be found at [identiguy.i2p](http://identiguy.i2p).

### Host anonymous website


If you wish to run your own website in Invisible Internet, follow those steps:

1) Run your webserver and find out which host:port it uses (for example, 127.0.0.1:8080).

2) Configure i2pd to create HTTP server tunnel. Put in your ~/.i2pd/tunnels.conf file:

        [anon-website]
        type = http
        host = 127.0.0.1
        port = 8080
        keys = anon-website.dat

3) Restart i2pd.

4) Find b32 destination of your website.

    Go to webconsole -> [I2P tunnels page](http://127.0.0.1:7070/?page=i2p_tunnels). Look for Sever tunnels and you will see address like \<long random string\>.b32.i2p next to anon-website.

    Website is now available in Invisible Internet by visiting this address.

5) (Optional) Register short and rememberable .i2p domain on [inr.i2p](http://inr.i2p).


## Using and hosting chat servers

### Running anonymous IRC server

1) Run your IRC server software and find out which host:port it uses (for example, 127.0.0.1:5555).

    For small private IRC servers you can use [miniircd](https://github.com/jrosdahl/miniircd), for large public networks [UnreadIRCd](https://www.unrealircd.org/).

2) Configure i2pd to create IRC server tunnel.

    Simplest case, if your server does not support WebIRC, add this to ~/.i2pd/tunnels.conf:

        [anon-chatserver]
        type = irc
        host = 127.0.0.1     
        port = 5555
        keys = chatserver-key.dat

    And that is it.

    Alternatively, if your IRC server supports WebIRC, for example, UnreadIRCd, put this into UnrealIRCd config:

        webirc {
            mask 127.0.0.1;
            password your_password;
        };

    Also change line:

        modes-on-connect "+ixw";

    to

        modes-on-connect "+iw";

    And this in ~/.i2pd/tunnels.conf:

        [anon-chatserver]
        type = irc
        host = 127.0.0.1
        port = 5555
        keys = chatserver-key.dat
        webircpassword = your_password

3) Restart i2pd.

4) Find b32 destination of your anonymous IRC server.

    Go to webconsole -> [I2P tunnels page](http://127.0.0.1:7070/?page=i2p_tunnels). Look for Sever tunnels and you will see address like \<long random string\>.b32.i2p next to anon-chatserver.

    Clients will use this address to connect to your server anonymously.

### Connect to anonymous IRC server

To connect to IRC server at *walker.i2p*, add this to ~/.i2pd/tunnels.conf:

    [IRC2]
    type = client
    address = 127.0.0.1
    port = 6669
    destination = walker.i2p
    #keys = walker-keys.dat

Restart i2pd, then connect to irc://127.0.0.1:6669 with your IRC client.

## File sharing

You can share and download torrents with [Transmission-I2P](https://github.com/l-n-s/transmission-i2p).

Alternative torrent-clients are [Robert](http://en.wikipedia.org/wiki/Robert_%28P2P_Software%29) and [Vuze](https://en.wikipedia.org/wiki/Vuze).

Robert uses BOB protocol, i2pd must be run with parameter --bob.enabled=true.

Vuze uses I2CP protocol, i2pd must be run with parameter --i2cp.enabled=true.

Also, visit [postman tracker](http://tracker2.postman.i2p).
