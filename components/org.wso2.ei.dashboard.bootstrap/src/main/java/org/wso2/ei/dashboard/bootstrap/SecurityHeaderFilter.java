/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.ei.dashboard.bootstrap;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

/**
 * This class is responsible for adding the security headers for the HTTP responses.
 */
public class SecurityHeaderFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        final HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
        // Allow the dashboard to frame its own pages ('self'/SAMEORIGIN) while still blocking framing by other
        // origins. Same-origin framing is required for the OIDC silent token renewal flow used with web worker
        // storage: it loads the IdP's prompt=none response in a hidden iframe that navigates to the dashboard's own
        // SSO redirect page. 'none'/DENY blocks that iframe and breaks session restore on a browser reload.
        httpResponse.addHeader("Content-Security-Policy", "frame-ancestors 'self'; object-src 'none';");
        httpResponse.addHeader("X-Frame-Options", "SAMEORIGIN");
        httpResponse.addHeader("X-Content-Type-Options", "nosniff");
        httpResponse.addHeader("Referrer-Policy", "same-origin");
        httpResponse.addHeader("X-XSS-Protection", "1; mode=block");
        httpResponse.addHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        httpResponse.addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        filterChain.doFilter(servletRequest, servletResponse);

    }

    @Override
    public void destroy() {

    }
}
