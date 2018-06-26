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

import Reflux from 'reflux';

import CrowdAuthActions from 'CrowdAuthActions';

import UserNotification from 'util/UserNotification';
import URLUtils from 'util/URLUtils';
import fetch from 'logic/rest/FetchProvider';

const urlPrefix = '/plugins/org.graylog.plugins.auth.crowd.sso';

const CrowdAuthStore = Reflux.createStore({
  listenables: [CrowdAuthActions],

  getInitialState() {
    return {
      config: undefined,
    };
  },

  _errorHandler(message, title, cb) {
    return (error) => {
      let errorMessage;
      try {
        errorMessage = error.additional.body.message;
      } catch (e) {
        errorMessage = error.message;
      }
      UserNotification.error(`${message}: ${errorMessage}`, title);
      if (cb) {
        cb(error);
      }
    };
  },

  _url(path) {
    return URLUtils.qualifyUrl(`${urlPrefix}${path}`);
  },

  config() {
    const promise = fetch('GET', this._url('/config'));

    promise.then((response) => {
      this.trigger({ config: response });
    }, this._errorHandler('Fetching config failed', 'Could not retrieve Crowd authenticator config'));

    CrowdAuthActions.config.promise(promise);
  },

  saveConfig(config) {
    const promise = fetch('PUT', this._url('/config'), config);

    promise.then((response) => {
      this.trigger({ config: response });
      UserNotification.success('Crowd configuration was updated successfully');
    }, this._errorHandler('Updating Crowd config failed', 'Unable to update Crowd authenticator config'));

    CrowdAuthActions.saveConfig.promise(promise);
  },
});

export default CrowdAuthStore;
