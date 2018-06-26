/**
*
* @licstart  The following is the entire license notice for the JavaScript code in this file.
*
* Crowd SSO authentication plugin for Graylog
*
* Copyright (C) 2018 University Of Helsinki (The National Library Of Finland)
*
* This file is part of graylog-plugin-auth-crowd-sso
*
* graylog-plugin-auth-crowd-sso program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* graylog-plugin-auth-crowd-sso is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU eneral Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* @licend  The above is the entire license notice
* for the JavaScript code in this file.
*
*/

// eslint-disable-next-line no-unused-vars
import webpackEntry from 'webpack-entry';

import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import CrowdConfiguration from "./CrowdConfiguration";

PluginStore.register(new PluginManifest(packageJson, {
  authenticatorConfigurations: [
    {
      name: 'crowd-sso',
      displayName: 'Atlassian Crowd (SSO)',
      description: 'Creates and authenticates users based on Crowd SSO token',
      canBeDisabled: true,
      component: CrowdConfiguration,
    },
  ]
}));
