Third-I backend
===============

A backend for the thingy.

Quick Start
-----------

### Prerequisites

 *  pipenv

### Development

Install all the dependencies:

```
pipenv install --dev
```

Run the dev server, example command:

```
CONFIG=/tmp/stereopi.conf \
    CAPTIVE_PORTAL=/run/captive-portal.sock \
    MEDIA=/tmp/media \
    SERIAL=/tmp/writer \
    pipenv run dev
```

 *  `CONFIG` is the path to a stereopi.conf. Normally located in /boot on the
    StereoPi
 *  `CAPTIVE_PORTAL` is the path to the Unix socket of the captive portal. See
    [the captive portal](https://github.com/BigBoySystems/captive-portal) for
    more information
 *  `MEDIA` is the path to a directory containing the videos and pictures,
    usually /media on the StereoPi
 *  `SERIAL`, optional, path to the serial device (the thingy with the buttons
    and the screen)
