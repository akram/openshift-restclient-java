/******************************************************************************* 
 * Copyright (c) 2016 Red Hat, Inc. 
 * Distributed under license by Red Hat, Inc. All rights reserved. 
 * This program is made available under the terms of the 
 * Eclipse Public License v1.0 which accompanies this distribution, 
 * and is available at http://www.eclipse.org/legal/epl-v10.html 
 * 
 * Contributors: 
 * Red Hat, Inc. - initial API and implementation 
 ******************************************************************************/
package com.openshift.internal.restclient.okhttp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;

import com.openshift.internal.restclient.DefaultClient;
import com.openshift.internal.restclient.authorization.AuthorizationDetails;
import com.openshift.internal.util.URIUtils;
import com.openshift.restclient.IClient;
import com.openshift.restclient.authorization.IAuthorizationContext;
import com.openshift.restclient.authorization.IAuthorizationDetails;
import com.openshift.restclient.authorization.UnauthorizedException;
import com.openshift.restclient.http.IHttpConstants;

import okhttp3.Authenticator;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Request.Builder;
import okhttp3.Response;
import okhttp3.Route;

/**
 * OkHttp Authenticator implementations for OpenShift 3
 * @author jeff.cantrill
 *
 */
public class OpenShiftAuthenticator implements Authenticator, IHttpConstants{
    public static final Logger LOGGER = Logger.getLogger(OpenShiftAuthenticator.class.getName());
	public static final String ACCESS_TOKEN = "access_token";

	private static final String AUTH_ATTEMPTS = "X-OPENSHIFT-AUTH-ATTEMPTS";
	private static final String CSRF_TOKEN = "X-CSRF-Token";
	private static final String ERROR = "error";
	private static final String ERROR_DETAILS = "error_details";
	
	private Collection<IChallangeHandler> challangeHandlers = new ArrayList<>();
	private OkHttpClient okClient;
	private IClient client;
	
	@Override
	public Request authenticate(Route route, Response response) throws IOException {
		LOGGER.fine("Executing method: authenticate");
		if(unauthorizedForCluster(response)){
			LOGGER.fine("Building authRequest");
			String requestUrl = response.request().url().toString();
			Request authRequest = new Request.Builder()
					.addHeader(CSRF_TOKEN, "1")
					.url(route.address().url().toString() + "oauth/authorize?response_type=token&client_id=openshift-challenging-client")
					.build();
			LOGGER.fine(String.format("AuthRequest: %s", authRequest));
			try (
				Response authResponse = tryAuth(authRequest)){
				if(authResponse.isSuccessful()) {
					LOGGER.fine("AuthResponse is successful: extracting token");
					String token = extractAndSetAuthContextToken(authResponse);
					return response.request().newBuilder()
							.header(IHttpConstants.PROPERTY_AUTHORIZATION, String.format("%s %s", IHttpConstants.AUTHORIZATION_BEARER, token))
							.build();
				}
			}
			throw new UnauthorizedException(captureAuthDetails(requestUrl), ResponseCodeInterceptor.getStatus(response.body().string()));
		}

		return null;
	}
	
	private boolean unauthorizedForCluster(Response response) {
		String requestHost = response.request().url().host();
		return response.code() == IHttpConstants.STATUS_UNAUTHORIZED && client.getBaseURL().getHost().equals(requestHost);
	}
	
	private Response tryAuth(Request authRequest) throws IOException {
		LOGGER.fine("Executing method: authenticate with authentication request: " + authRequest);
		Authenticator authenticator = new Authenticator() {
			@Override
			public Request authenticate(Route route, Response response) throws IOException {
			    LOGGER.fine("Authenticating in " + this.getClass().getName() + " : authenticate");
                LOGGER.fine("AUTH_ATTEMPTS:  " + AUTH_ATTEMPTS);
				if(StringUtils.isNotBlank(response.request().header(AUTH_ATTEMPTS))) {
	                LOGGER.fine("Returning null as we tried alread to authenticate");
					return null;
				}
				if(StringUtils.isNotBlank(response.header(PROPERTY_WWW_AUTHENTICATE))) {
                    LOGGER.fine("Header " + PROPERTY_WWW_AUTHENTICATE + " found in response. Will try remaining handlers: " + challangeHandlers);
					for (IChallangeHandler challangeHandler : challangeHandlers) {
	                    LOGGER.fine("Challenge handler " + challangeHandler + " can handle it?");
						if(!challangeHandler.canHandle(response.headers())) {
       	                    LOGGER.fine("Challenge handler " + challangeHandler + " can not handle it: So we will handle it. (well yes this is a bug)");
							Builder requestBuilder = response.request().newBuilder().header(AUTH_ATTEMPTS, "1");
                            LOGGER.fine("Let's keep a track that we try a challenge once: setting AUTH_ATTEMPTS to 1 in request" );
							Request handledResponse = challangeHandler.handleChallange(requestBuilder).build();
                            LOGGER.fine("Returning handled response: " + handledResponse);
                            return handledResponse;
						}
					}
				}
                LOGGER.fine("Returning null response: PROPERTY_WWW_AUTHENTICATE was not found in header");
				return null;
			}
		};
        Call configuredOkClientCall = okClient.newBuilder().authenticator(authenticator).followRedirects(false).followRedirects(false).build().newCall(authRequest);
        LOGGER.fine("About to execute the client call: " + configuredOkClientCall);
        return configuredOkClientCall.execute();
	}
	
	private IAuthorizationDetails captureAuthDetails(String url) {
		IAuthorizationDetails details = null;
		Map<String, String> pairs = URIUtils.splitFragment(url);
		if (pairs.containsKey(ERROR)) {
			details = new AuthorizationDetails(pairs.get(ERROR), pairs.get(ERROR_DETAILS));
		}
		return details;
	}
	
	private String extractAndSetAuthContextToken(Response response) {
		String token = null;
		Map<String, String> pairs = URIUtils.splitFragment(response.header(PROPERTY_LOCATION));
		if (pairs.containsKey(ACCESS_TOKEN)) {
			token = pairs.get(ACCESS_TOKEN);
			IAuthorizationContext authContext = client.getAuthorizationContext();
			if(authContext != null) {
				authContext.setToken(token);
			}
		}
		return token;
	}
	

	public void setOkClient(OkHttpClient okClient) {
		this.okClient = okClient;
	}

	public void setClient(DefaultClient client) {
		this.client = client;
		challangeHandlers.clear();
		challangeHandlers.add(new BasicChallangeHandler(client.getAuthorizationContext()));
	}

}
