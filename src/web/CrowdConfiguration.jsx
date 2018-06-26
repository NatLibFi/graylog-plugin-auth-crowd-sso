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

import React from "react";
import Reflux from "reflux";
import { Row, Col, Button, Alert } from "react-bootstrap";
import { Input } from 'components/bootstrap';

import { PageHeader, Spinner } from "components/common";
import CrowdAuthActions from "CrowdAuthActions";
import CrowdAuthStore from "CrowdAuthStore";

import StoreProvider from 'injection/StoreProvider';

import ObjectUtils from 'util/ObjectUtils';

const CrowdConfiguration = React.createClass({
  mixins: [
    Reflux.connect(CrowdAuthStore),
  ],

  componentDidMount() {
    CrowdAuthActions.config();
  },

  _saveSettings(ev) {
    ev.preventDefault();
    CrowdAuthActions.saveConfig(this.state.config);
  },

  _setSetting(attribute, value) {
    const newState = {};

    // Clone state to not modify it directly
    const settings = ObjectUtils.clone(this.state.config);
    settings[attribute] = value;
    newState.config = settings;
    this.setState(newState);
  },

  _bindChecked(ev, value) {
    this._setSetting(ev.target.name, typeof value === 'undefined' ? ev.target.checked : value);
  },

  _bindValue(ev) {
    this._setSetting(ev.target.name, ev.target.value);
  },

  render() {
    let content;
    if (!this.state.config) {
      content = <Spinner />;
    } else {
      content = (
        <Row>
          <Col lg={8}>
            <form id="crowd-sso-config-form" className="form-horizontal" onSubmit={this._saveSettings}>
              <fieldset>
                <legend className="col-sm-12">API configuration</legend>
                <Input type="text" id="api_url" name="api_url" labelClassName="col-sm-3"
                       wrapperClassName="col-sm-9" placeholder="API URL" label="API URL"
                       value={this.state.config.api_url} help="URL of Crowd server API endpoint"
                       onChange={this._bindValue} required/>
                <Input type="text" id="app_name" name="app_name" labelClassName="col-sm-3"
                      wrapperClassName="col-sm-9" placeholder="Application name" label="Application name"
                      value={this.state.config.app_name} help="Crowd application name"
                      onChange={this._bindValue} required/>
                <Input type="password" id="app_password" name="app_password" labelClassName="col-sm-3"
                      wrapperClassName="col-sm-9" placeholder="Application password" label="Application password"
                      value={this.state.config.app_password} help="Crowd application password"
                      onChange={this._bindValue} required/>
                <Input type="text" id="cookie_name" name="cookie_name" labelClassName="col-sm-3"
                      wrapperClassName="col-sm-9" placeholder="Crowd cookie name" label="Crowd cookie name"
                      value={this.state.config.cookie_name} help="Crowd SSO cookie name"
                      onChange={this._bindValue} required/>
                <Input type="checkbox" label="Verify API certificate"
                       help="Enable this if Crowd API server certificate should be verified."
                       wrapperClassName="col-sm-offset-3 col-sm-9"
                       name="api_verify_cert"
                       checked={this.state.config.api_verify_cert}
                       onChange={this._bindChecked}/>
              </fieldset>
              <fieldset>
                <legend className="col-sm-12">User & role creation</legend>
                <Input type="checkbox" label="Automatically create users"
                       help="Enable this if Graylog should automatically create a user account for externally authenticated users. If disabled, an administrator needs to manually create a user account."
                       wrapperClassName="col-sm-offset-3 col-sm-9"
                       name="auto_create_user"
                       checked={this.state.config.auto_create_user}
                       onChange={this._bindChecked}/>
                <Input type="checkbox" label="Automatically create roles"
                      help="Enable this if Graylog should automatically create and assign roles based on user's groups"
                      wrapperClassName="col-sm-offset-3 col-sm-9"
                      name="auto_create_role"
                      checked={this.state.config.auto_create_role}
                      onChange={this._bindChecked}/>
              </fieldset>
              <fieldset>
                <legend className="col-sm-12">Store settings</legend>
                <div className="form-group">
                  <Col sm={9} smOffset={3}>
                    <Button type="submit" bsStyle="success">Save Crowd settings</Button>
                  </Col>
                </div>
              </fieldset>
            </form>
          </Col>
        </Row>
      );
    }

    return (
      <div>
        <PageHeader title="Atlassian Crowd Configuration" subpage>
          <span>Configuration page for the Crowd authenticator.</span>
          {null}
        </PageHeader>
        {content}
      </div>
    );
  },
});

export default CrowdConfiguration;
