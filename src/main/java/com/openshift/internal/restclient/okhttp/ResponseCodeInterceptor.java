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
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;

import com.openshift.internal.restclient.DefaultClient;
import com.openshift.internal.restclient.authorization.AuthorizationDetails;
import com.openshift.internal.restclient.model.Status;
import com.openshift.internal.util.URIUtils;
import com.openshift.restclient.BadRequestException;
import com.openshift.restclient.IClient;
import com.openshift.restclient.NotFoundException;
import com.openshift.restclient.OpenShiftException;
import com.openshift.restclient.authorization.ResourceForbiddenException;
import com.openshift.restclient.http.IHttpConstants;
import com.openshift.restclient.model.IStatus;

import okhttp3.Interceptor;
import okhttp3.Response;

/**
 * Interpret response codes and handle accordingly
 * 
 * @author jeff.cantrill
 *
 */
public class ResponseCodeInterceptor implements Interceptor, IHttpConstants {
	
	public static final String X_OPENSHIFT_IGNORE_RCI = "X-OPENSHIFT-IGNORE-RCI";

	private static final Logger LOGGER = Logger.getLogger(ResponseCodeInterceptor.class.getName());
	
	private IClient client;

	/**
	 * If a request tag() implements this interface, HTTP errors
	 * will not throw OpenShift exceptions.
	 */
	public interface Ignore{}


	@Override
	public Response intercept(Chain chain) throws IOException {
		Response response = chain.proceed(chain.request());
		if(!response.isSuccessful() && StringUtils.isBlank(response.request().header(X_OPENSHIFT_IGNORE_RCI))) {
            int code = response.code();
            LOGGER.fine("Response is not succesful: response code : " + code);
            switch(code) {
			case STATUS_UPGRADE_PROTOCOL:
			case STATUS_MOVED_PERMANENTLY:
				break;
			case STATUS_MOVED_TEMPORARILY:
				response = makeSuccessIfAuthorized(response);
		        LOGGER.fine("Making response as being authorized: " + response);
				break;
			default:
				if ( response.request().tag() instanceof Ignore == false ) {
				    LOGGER.fine("Response is not any of the expected codes and header not set to ignore: " + response.body());
					OpenShiftException openShiftException = createOpenShiftException(client, response, null);
	                LOGGER.fine("Return the exception: " + openShiftException);
                    throw openShiftException;
				}
			}
		}
        LOGGER.fine("Returning response: " + response);
		return response;
	}
	
	private Response makeSuccessIfAuthorized(Response response) {
		String location = response.header(PROPERTY_LOCATION);
        LOGGER.fine("Getting access token from location: " + location);
		if(StringUtils.isNotBlank(location) && URIUtils.splitFragment(location).containsKey(OpenShiftAuthenticator.ACCESS_TOKEN)) {
			response = response.newBuilder()
				.request(response.request())
				.code(STATUS_OK)
				.headers(response.headers())
				.build();
		}
		return response;
	}

	public void setClient(DefaultClient client) {
		this.client = client;
	}
	
	public static IStatus getStatus(String response) {
	     IStatus status = null;
         if(response != null && response.startsWith("{")) {
			status =  new Status(response);
		}
         LOGGER.fine("response status is : " + status);
        return status ;
	}
	
	public static OpenShiftException createOpenShiftException(IClient client, Response response, Throwable e) throws IOException{
		LOGGER.fine("Response: " + response + "stackTrace: " + e);
	    if( e != null ) {
	        LOGGER.fine("Response: " + response + "stackTrace: " + e.getStackTrace());
	    }

		IStatus status = getStatus(response.body().string());
		int responseCode = response.code();
		if(status != null && status.getCode() != 0) {
			responseCode = status.getCode();
		}
        LOGGER.fine("Response code : " + responseCode);
		switch(responseCode) {
		case STATUS_BAD_REQUEST:
			return new BadRequestException(e, status, response.request().url().toString());
		case STATUS_FORBIDDEN:
			return new ResourceForbiddenException(status != null ? status.getMessage() : "Resource Forbidden", status, e);
		case STATUS_UNAUTHORIZED:
			String link = String.format("%s/oauth/token/request", client.getBaseURL());
	        LOGGER.fine("Link URL: " + link);
	        LOGGER.fine("Request URL: " + response.request().url());
			AuthorizationDetails details = new AuthorizationDetails(response.headers(), link);
	        LOGGER.fine("Response: Unauthorized: AuthorizationDetails: " + details);
			return new com.openshift.restclient.authorization.UnauthorizedException(details, status);
		case IHttpConstants.STATUS_NOT_FOUND:
			return new NotFoundException(e, status, status == null ? "Not Found" : status.getMessage());
		default:
			return new OpenShiftException(e, status, "Exception trying to %s %s response code: %s", response.request().method(), response.request().url().toString(), responseCode);
		}
	}

	public static OpenShiftException createOpenShiftException(IClient client, int responseCode, String message, String response, Throwable e) throws IOException{
        LOGGER.fine("response: " + response + "stackTrace: " + e.getStackTrace());
		IStatus status = getStatus(response);
		if(status != null && status.getCode() != 0) {
			responseCode = status.getCode();
		}
		switch(responseCode) {
		case STATUS_BAD_REQUEST:
			return new BadRequestException(e, status, response);
		case STATUS_FORBIDDEN:
			return new ResourceForbiddenException(status != null ? status.getMessage() : "Resource Forbidden", status, e);
		case STATUS_UNAUTHORIZED:
			return new com.openshift.restclient.authorization.UnauthorizedException(client.getAuthorizationContext().getAuthorizationDetails(), status);
		case IHttpConstants.STATUS_NOT_FOUND:
			return new NotFoundException(status == null ? "Not Found" : status.getMessage());
		default:
			return new OpenShiftException(e, status, "Exception trying to fetch %s response code: %s", response, responseCode);
		}
	}
	
	
}
