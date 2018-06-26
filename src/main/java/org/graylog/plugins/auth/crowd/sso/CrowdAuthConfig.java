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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;

import javax.annotation.Nullable;

@AutoValue
@JsonDeserialize(builder = AutoValue_CrowdAuthConfig.Builder.class)
@JsonAutoDetect
public abstract class CrowdAuthConfig {

    public static Builder builder() {
        return new AutoValue_CrowdAuthConfig.Builder();
    }

    public abstract Builder toBuilder();

    public static CrowdAuthConfig defaultConfig() {
        return builder()
                .cookieName("crowd.token_key")
                .apiVerifyCert(true)
                .autoCreateUser(true)
                .autoCreateRole(false)
                .build();
    }

    @JsonProperty("api_url")
    @Nullable
    public abstract String apiUrl();

    @JsonProperty("app_name")
    @Nullable
    public abstract String applicationName();

    @JsonProperty("app_password")
    @Nullable
    public abstract String applicationPassword();

    @JsonProperty("cookie_name")
    @Nullable
    public abstract String cookieName();

    @JsonProperty("api_verify_cert")
    public abstract boolean apiVerifyCert();

    @JsonProperty("auto_create_user")
    public abstract boolean autoCreateUser();

    @JsonProperty("auto_create_role")
    public abstract boolean autoCreateRole();

    @AutoValue.Builder
    public static abstract class Builder {
        abstract CrowdAuthConfig build();

        @JsonProperty("api_url")
        public abstract Builder apiUrl(@Nullable String apiUrl);

        @JsonProperty("app_name")
        public abstract Builder applicationName(@Nullable String applicationName);

        @JsonProperty("app_password")
        public abstract Builder applicationPassword(@Nullable String applicationPassword);

        @JsonProperty("cookie_name")
        public abstract Builder cookieName(@Nullable String cookieName);

        @JsonProperty("api_verify_cert")
        public abstract Builder apiVerifyCert(boolean apiVerifyCert);

        @JsonProperty("auto_create_user")
        public abstract Builder autoCreateUser(boolean autoCreateUser);

        @JsonProperty("auto_create_role")
        public abstract Builder autoCreateRole(boolean autoCreateRole);
    }
}
