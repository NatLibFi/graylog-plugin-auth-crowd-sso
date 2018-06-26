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

package org.graylog.plugins.auth.crowd.sso.audit;

import com.google.common.collect.ImmutableSet;
import org.graylog2.audit.PluginAuditEventTypes;

import java.util.Set;

public class CrowdAuthAuditEventTypes implements PluginAuditEventTypes {
    private static final String NAMESPACE = "crowd_sso_auth:";

    public static final String CONFIG_UPDATE = NAMESPACE + "config:update";

    private static final Set<String> EVENT_TYPES = ImmutableSet.<String>builder()
            .add(CONFIG_UPDATE)
            .build();

    @Override
    public Set<String> auditEventTypes() {
        return EVENT_TYPES;
    }
}
