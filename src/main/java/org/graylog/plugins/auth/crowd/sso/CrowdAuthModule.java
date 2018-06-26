/**
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
*/
package org.graylog.plugins.auth.crowd.sso;

import com.google.inject.Scopes;
import org.graylog.plugins.auth.crowd.sso.audit.CrowdAuthAuditEventTypes;
import org.graylog2.plugin.PluginModule;

/**
 * Extend the PluginModule abstract class here to add you plugin to the system.
 */
public class CrowdAuthModule extends PluginModule {

    @Override
    protected void configure() {
        authenticationRealmBinder().addBinding(CrowdAuthRealm.NAME).to(CrowdAuthRealm.class).in(Scopes.SINGLETON);
        addRestResource(CrowdConfigResource.class);
        addPermissions(CrowdAuthPermissions.class);
        addAuditEventTypes(CrowdAuthAuditEventTypes.class);
    }
}
