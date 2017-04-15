# TLS Ruleset Enforcer Daemon

TLSD analyses TCP streams, identifies TLS handshakes in them and evaluates a dynamic ruleset before the first encrypted application data is exchanged. The ruleset determines whether the TLS session is allowed to exchange data, or whether the TLS session is rejected and the underlying TCP connection closed.

## Prerequisites

* Python 2.7
* OpenBSD pf(4)

The only supported operating system is OpenBSD, because that's what I'm experimenting with at the moment. However, the application can easily be ported to other operating systems (check out the existing "diverters" in the `tlsd/diverters` directory).

## Installation from Source

This project follows the official instructions for [Packaging and Distributing Projects](https://packaging.python.org/distributing/) in Python. This means that you can build and install the `tlsd` command on your system, directly from the sources in this directory with:

    python setup.py install

If you have multiple versions of Python installed, then you may have to specify the version explicitly, e.g.:

    python2.7 setup.py install

## Usage on OpenBSD

Add the following line to `/etc/pf.conf`:

    pass on { egress } inet proto tcp from any to any divert-to 127.0.0.1 port 7000

and then start the daemon with:

    tlsd -l 7000

At this point all incoming and outgoing TCP connections are analysed by TLSD. Those that use either HTTPS or other protocols with Transport Layer Security (except STARTTLS, yet) and fail to match the default ruleset will be terminated before any application data can be exchanged; all other connections are simply passed through, and should not incur any performance overhead at all.

*Note*: Due to the experimental status of the software, the "daemon" will not actually fork and detach from the controlling terminal, but will run in the foreground and pring log messages to standard output.

## Development

Run the test suite with:

```
python setup.py test
```

## Contributing

Please submit your ideas and issues at https://github.com/ustuehler/tlsd/issues.
