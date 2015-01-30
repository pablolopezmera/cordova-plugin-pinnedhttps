package me.lockate.plugins;

import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import java.util.Map;
import java.util.List;
import java.util.LinkedList;
import java.util.Set;
import java.util.Iterator;
import java.lang.StringBuffer;
import java.lang.StackTraceElement;

import java.util.concurrent.RejectedExecutionException;
import java.lang.NullPointerException;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.DataOutputStream;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.UnknownServiceException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;

public class PinnedHTTPS extends CordovaPlugin {

	private final static String logTag = "PinnedHTTPS";

	@Override
	public boolean execute(final String method, final JSONArray args, final CallbackContext callbackContext) throws RejectedExecutionException, NullPointerException {//JSONException, IOException, NoSuchAlgorithmException{ //, CertificateException{ //, CertificateEncodingException {
		if (method.equals("get")){
			//Standard HTTPS GET request. Running in a new thread
			cordova.getThreadPool().execute(new Runnable(){
				public void run(){
					String getUrlStr = ""; //Request URL
					String fingerprintsArrayStr = ""; //Expected fingerprints
					JSONArray fingerprintsJson;
					List<String> fingerprints = new LinkedList<String>();
					try {
						getUrlStr = args.getString(0);
						fingerprintsArrayStr = args.getString(1);
						fingerprintsJson = new JSONArray(fingerprintsArrayStr);
						for (int i = 0; i < fingerprintsJson.length(); i++) fingerprints.add(fingerprintsJson.getString(i));
					} catch (JSONException e){
						callbackContext.error("INVALID_PARAMS");
						return;
					}

					Log.v(logTag, "getUrlStr: " + getUrlStr + "\n" + "fingerprints: " + fingerprintsArrayStr);

					URL getUrl;
					try {
						getUrl = new URL(getUrlStr);
					} catch (MalformedURLException e){
						callbackContext.error("INVALID_URL");
						return;
					}
					final String hostname = getUrl.getHost(); //Getting hostname from URL
					HttpsURLConnection conn;
					try {
						conn = (HttpsURLConnection) getUrl.openConnection();
					} catch (IOException e){
						callbackContext.error("CANT_CONNECT");
						return;
					}
					Log.v(logTag, "Connection instanciated");
					//Setting up the fingerprint verification upon session negotiation
					try {
						conn.setUseCaches(false);
						Log.v(logTag, "Disabled cache");

						TrustManager tm[] = { new HashTrust(fingerprints) };
						SSLContext connContext = SSLContext.getInstance("TLS");
						connContext.init(null, tm, null);
						conn.setSSLSocketFactory(connContext.getSocketFactory());
						Log.v(logTag, "Hash-based trust manager has been set");

						conn.setHostnameVerifier(new HostnameVerifier(){
							public boolean verify(String connectedHostname, SSLSession sslSession){
								return true;
							}
						});
						Log.v(logTag, "Blank hostname verifier has been set");

					} catch (Exception e){
						Log.v(logTag, "Error while setting up the conneciton: " + e.toString());
						callbackContext.error("CANT_CONNECT");
						return;
					}
					//Open connection and process request
					try {
						conn.connect();
						Log.v(logTag, "Connection now open");
					} catch (SocketTimeoutException e){
						//callbackContext.error("Cannot connect to " + getUrlStr + " (timeout)");
						callbackContext.error("TIMEOUT");
						return;
					} catch (IOException e){
						if (e.getMessage().indexOf("INVALID_CERT") > -1) callbackContext.error("INVALID_CERT");
						else callbackContext.error("CANT_CONNECT");
						Log.v(logTag, "IOException:\n" + getStackTraceStr(e));
						return;
					}
					try {
						int httpStatusCode = conn.getResponseCode();
						Map<String, List<String>> responseHeaders = conn.getHeaderFields();
						BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
						StringBuffer response = new StringBuffer();
						String currentLine;
						Log.v(logTag, "Reading response");
						while ((currentLine = reader.readLine()) != null){
							response.append(currentLine);
						}
						reader.close();
						conn.disconnect();

						Log.v(logTag, "Building response object");
						JSONObject responseObj;
						try {
							responseObj = buildResponseJson(httpStatusCode, response.toString(), responseHeaders);
						} catch (JSONException e){
							callbackContext.error("INTERNAL_ERROR");
							Log.v(logTag, "Error while building response object: " + e.toString());
							return;
						}
						if (responseObj == null) callbackContext.error("INTERNAL_ERROR");
						else callbackContext.success(responseObj.toString());
						Log.v(logTag, "End of get");
					} catch (Exception e){
						callbackContext.error("INTERNAL_ERROR");
						//callbackContext.error("Error while building response object: " + e.toString());
					}
				}
			});
			return true;
		} else if (method.equals("req")){
			//Arbitrary HTTP request (any verb)
			cordova.getThreadPool().execute(new Runnable(){
				public void run(){
					JSONObject reqOptions;
					String fingerprintsArrayStr = "", hostname = "", port = "", path = "", httpMethod = "";
					JSONArray fingerprintsJson;
					List<String> fingerprints = new LinkedList<String>();
					try {
						reqOptions = new JSONObject(args.getString(0));
						hostname = reqOptions.getString("host");
						port = reqOptions.getString("port");
						path = reqOptions.getString("path");
						httpMethod = reqOptions.getString("method");

						fingerprintsArrayStr = args.getString(1);
						fingerprintsJson = new JSONArray(fingerprintsArrayStr);
						for (int i = 0; i < fingerprintsJson.length(); i++) fingerprints.add(fingerprintsJson.getString(i));
					} catch (JSONException e){
						callbackContext.error("INVALID_PARAMS");
						return;
					}

					httpMethod = httpMethod.toUpperCase();
					if (!(httpMethod.equals("GET") || httpMethod.equals("POST") || httpMethod.equals("DELETE") || httpMethod.equals("PUT") || httpMethod.equals("HEAD") || httpMethod.equals("OPTIONS") || httpMethod.equals("PATCH") || httpMethod.equals("TRACE") || httpMethod.equals("CONNECT"))){
						callbackContext.error("INVALID_METHOD");
						return;
					}

					String reqUrlStr = "https://" + hostname + ":" + port + path;
					Log.v(logTag, "reqUrlStr: " + reqUrlStr + "\nMethod: " + httpMethod + "\nfingerprints: " + fingerprintsArrayStr);
					URL reqUrl = initURL(reqUrlStr);
					HttpsURLConnection conn;
					try {
						conn = (HttpsURLConnection) reqUrl.openConnection();
					} catch (IOException e){
						callbackContext.error("CANT_CONNECT");
						return;
					}
					Log.v(logTag, "Connection instanciated");
					//Append headers, if any
					if (reqOptions.has("headers")){
						Log.v(logTag, "Headers provided. Reading them");
						JSONObject headers;
						try {
							headers = reqOptions.getJSONObject("headers");
						} catch (JSONException e){
							callbackContext.error("INVALID_HEADERS");
							return;
						}
						try {
							JSONArray headersNames = headers.names();
							for (int i = 0; i < headersNames.length(); i++){
								String currentHeaderName = headersNames.getString(i);
								conn.addRequestProperty(currentHeaderName, headers.getString(currentHeaderName));
							}
						} catch (Exception e){
							callbackContext.error("INTERNAL_ERROR");
							return;
						}
					}
					//Set that I intend to use the received data
					conn.setDoInput(true);

					try {
						conn.setRequestMethod(httpMethod);
						conn.setUseCaches(false);
						Log.v(logTag, "Set the HTTP method to use. Disabled cache");

						TrustManager tm[] = { new HashTrust(fingerprints) };
						SSLContext connContext = SSLContext.getInstance("TLS");
						connContext.init(null, tm, null);
						conn.setSSLSocketFactory(connContext.getSocketFactory());
						Log.v(logTag, "Blank trust manager has been set");

						conn.setHostnameVerifier(new HostnameVerifier(){
							public boolean verify(String connectedHostname, SSLSession sslSession){
								return true;
							}
						});
						Log.v(logTag, "Blank hostname verifier has been set");

					} catch (Exception e){
						callbackContext.error("CANT_CONNECT");
						Log.v(logTag, "Error while setting up the connection: " + e.toString());
						return;
					}
					//Open connection and process request
					//Append body, if any
					if (reqOptions.has("body")){
						Log.v(logTag, "Request body provided. Append it to request");
						JSONObject body;
						try {
							body = reqOptions.getJSONObject("body");
						} catch (JSONException e){
							callbackContext.error("INVALID_BODY");
							return;
						}
						try {
							conn.setDoOutput(true);
							conn.setRequestProperty("Content-Type", "application/json");
							String bodyString = body.toString();
							DataOutputStream oStream = new DataOutputStream(conn.getOutputStream());
							oStream.writeBytes(bodyString);
							oStream.flush();
							oStream.close();
						} catch (SocketTimeoutException e){
							callbackContext.error("TIMEOUT");
							return;
						} catch (UnknownServiceException e){
							Log.v(logTag, "Unsupported body");
							callbackContext.error("INTERNAL_ERROR");
							return;
						} catch (IOException e){
							if (e.getMessage().indexOf("INVALID_CERT") > -1) callbackContext.error("INVALID_CERT");
							else callbackContext.error("CANT_CONNECT");
							Log.v(logTag, "IOException:\n" + getStackTraceStr(e));
							return;
						}
					} else { //No request body. Process request normally
						try {
							conn.connect();
							Log.v(logTag, "Connection is now open");
						} catch (SocketTimeoutException e){
							callbackContext.error("TIMEOUT");
							return;
						} catch (IOException e){
							if (e.getMessage().indexOf("INVALID_CERT") > -1) callbackContext.error("INVALID_CERT");
							else callbackContext.error("TIMEOUT");
							Log.v(logTag, "IOException:\n" + getStackTraceStr(e));
							return;
						}
					}

					try {
						int httpStatusCode = conn.getResponseCode();
						Map<String, List<String>> responseHeaders = conn.getHeaderFields();
						BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
						StringBuffer response = new StringBuffer();
						String currentLine;
						Log.v(logTag, "Reading response");
						while ((currentLine = reader.readLine()) != null){
							response.append(currentLine);
						}
						reader.close();
						conn.disconnect();

						Log.v(logTag, "Building response object");
						JSONObject responseObj;
						try {
							responseObj = buildResponseJson(httpStatusCode, response.toString(), responseHeaders);
						} catch (JSONException e){
							callbackContext.error("INTERNAL_ERROR");
							Log.v(logTag, "Error while building response object: " + e.toString());
							return;
						}
						if (responseObj == null) callbackContext.error("INTERNAL_ERROR");
						else callbackContext.success(responseObj.toString());
						Log.v(logTag, "End of req");
					} catch (Exception e){
						Log.v(logTag, "Error while building response object: " + e.toString());
						callbackContext.error("INTERNAL_ERROR");
					}
				}
			});
			return true;
		} else {
			callbackContext.error("Invalid method. Did you mean \"get()\" or \"req()\"?");
			return false;
		}
	}

	private static JSONObject buildResponseJson (final int responseCode, final String responseBody, Map<String, List<String>> responseHeaders) throws JSONException{
		JSONObject responseObj = new JSONObject();
		try {
			responseObj.put("statusCode", responseCode);
			responseObj.put("body", responseBody);

			JSONObject headersObj = new JSONObject();
			Set<Map.Entry<String, List<String>>> headersEntries = responseHeaders.entrySet();
			Iterator<Map.Entry<String, List<String>>> headersIterator = headersEntries.iterator();
			while (headersIterator.hasNext()){
				Map.Entry<String, List<String>> currentHeader = headersIterator.next();
				//Skip header field if values are empty
				if (currentHeader.getValue().size() == 0) continue;
				if (currentHeader.getKey() == "" || currentHeader.getKey() == null) continue;
				//Getting first values of header
				headersObj.put(currentHeader.getKey(), currentHeader.getValue().get(0));
			}
			responseObj.put("headers", headersObj);
		} catch (JSONException e){
			throw e;
		}
		return responseObj;
	}

	private static URL initURL(String s){
		try {
			return new URL(s);
		} catch (Exception e){
			return null;
		}
	}

	private static String getStackTraceStr(Exception e){
		StringBuffer s = new StringBuffer();
		s.append(e.getMessage() + "\n");
		StackTraceElement[] callstack = e.getStackTrace();
		for (int i = 0; i < callstack.length; i++){
			s.append(callstack[i].toString() + "\n");
		}
		return s.toString();
	}
}
