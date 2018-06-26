# Crowd SSO authentication plugin for Graylog [![Build Status](https://travis-ci.org/natlibfi/graylog-plugin-auth-crowd-sso.svg?branch=master)](https://travis-ci.org/natlibfi/graylog-plugin-auth-crowd-sso)

This plugin adds support for Atlassian Crowd SSO authentication and authorization.

Based on [graylog-plugin-auth-sso](https://github.com/graylog2/graylog-plugin-auth-sso)

**Required Graylog version:** 2.4.0 or later

Version Compatibility
---------------------

| Plugin Version | Graylog Version |
| -------------- | --------------- |
| 1.0.x          | 2.4.x           |

Installation
------------

Build (See `.travis.yml`) place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

Development
-----------

You can improve your development experience for the web interface part of your plugin
dramatically by making use of hot reloading. To do this, do the following:

* `git clone https://github.com/Graylog2/graylog2-server.git`
* `cd graylog2-server/graylog2-web-interface`
* `ln -s $YOURPLUGIN plugin/`
* `npm install && npm start`

## License and copyright

Copyright (c) 2018 **University Of Helsinki (The National Library Of Finland)**

Source code is licensed under the terms of **GNU General Public License Version 3** or any later version.
