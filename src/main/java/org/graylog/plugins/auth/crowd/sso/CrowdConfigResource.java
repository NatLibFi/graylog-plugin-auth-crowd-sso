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

import com.google.common.base.Joiner;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.graylog.plugins.auth.crowd.sso.audit.CrowdAuthAuditEventTypes;
import org.graylog2.audit.jersey.AuditEvent;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.rest.PluginRestResource;
import org.graylog2.shared.rest.resources.RestResource;
import org.graylog2.utilities.IpSubnet;

import javax.inject.Inject;
import javax.inject.Named;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Set;

@Api(value = "Crowd/SSO/Config", description = "Manage Crowd SSO authenticator configuration")
@Path("/config")
@Produces(MediaType.APPLICATION_JSON)
@RequiresAuthentication
public class CrowdConfigResource extends RestResource implements PluginRestResource {

    private final ClusterConfigService clusterConfigService;

    @Inject
    private CrowdConfigResource(ClusterConfigService clusterConfigService) {
        this.clusterConfigService = clusterConfigService;
    }

    @ApiOperation(value = "Get Crowd configuration")
    @GET
    @RequiresPermissions(CrowdAuthPermissions.CONFIG_READ)
    public CrowdAuthConfig get() {
        final CrowdAuthConfig config = clusterConfigService.getOrDefault(CrowdAuthConfig.class,
                                                                       CrowdAuthConfig.defaultConfig());
        return config.toBuilder().build();
    }

    @ApiOperation(value = "Update Crowd configuration")
    @Consumes(MediaType.APPLICATION_JSON)
    @PUT
    @RequiresPermissions(CrowdAuthPermissions.CONFIG_UPDATE)
    @AuditEvent(type = CrowdAuthAuditEventTypes.CONFIG_UPDATE)
    public CrowdAuthConfig update(@ApiParam(name = "config", required = true) @NotNull CrowdAuthConfig config) {
        final CrowdAuthConfig cleanConfig = config.toBuilder().build();
        clusterConfigService.write(cleanConfig);

        return config;
    }

}
