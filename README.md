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

### Sample data for the serial communication

```
[Hello]
[PARAM_ASK|audio_enabled|0xff]
[PARAM_ASK|audio_enabled|0x378c1418]
[PARAM_ASK|invalid_key|0x19359147]
[PARAM_SET|audio_enabled:1|0x3b95c0da]
[PARAM_SET|invalid_key:1|0x6bafad8b]
[WIFI_ON||0xb8514cc0]
[WIFI_OFF||0x3bd7cea7]
[REC_START||0x349c5788]
[REC_STOP||0xf0f9e341]
```
