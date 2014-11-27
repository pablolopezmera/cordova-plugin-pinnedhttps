package me.lockate.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.Iterator;

import java.util.concurrent.RejectedExecutionException;
import java.lang.NullPointerException;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;

public class PinnedHTTPS extends CordovaPlugin {

	private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

	@Override
	public boolean execute(final String method, final JSONArray args, final CallbackContext callbackContext) throws RejectedExecutionException, NullPointerException {//JSONException, IOException, NoSuchAlgorithmException{ //, CertificateException{ //, CertificateEncodingException {
		if (method.equals("get")){
			//Standard HTTPS GET request. Running in a new thread
			cordova.getThreadPool().execute(new Runnable(){
				public void run(){
					String getUrlStr; //Request URL
					String fingerprint; //Expected fingerprint
					try {
						getUrlStr = args.getString(0);
						fingerprint = args.getString(1);
					} catch (JSONException e){
						callbackContext.error("Invalid method parameters");
						return;
					}
					URL getUrl;
					try {
						getUrl = new URL(getUrlStr);
					} catch (MalformedURLException e){
						callbackContext.error("Invalid URL format");
						return;
					}
					final String hostname = getUrl.getHost(); //Getting hostname from URL
					HttpsURLConnection conn;
					try {
						conn = (HttpsURLConnection) getUrl.openConnection();
					} catch (IOException e){
						callbackContext.error("Cannot connect to " + getUrlStr);
						return;
					}
					//Setting up the fingerprint verification upon session negotiation
					try {
						conn.setUseCaches(false);
						final String f_hostname = hostname;
						final String f_fingerprint = fingerprint;
						conn.setDefaultHostnameVerifier(new HostnameVerifier(){
							public boolean verify(String connectedHostname, SSLSession sslSession){
								if (!connectedHostname.equals(f_hostname)){
									return false;
								}

								Certificate serverCert;
								MessageDigest md;
								try {
									serverCert = sslSession.getPeerCertificates()[0]; //Getting the servers own certificate
									md = MessageDigest.getInstance("SHA1"); //Instanciating SHA1
									md.update(serverCert.getEncoded());
								} catch (SSLPeerUnverifiedException e){
									callbackContext.error("Peer ceritifcate error. Cannot check identity. Kiling the connection");
									return false;
								} catch (NoSuchAlgorithmException e){
									callbackContext.error("Missing SHA1 support!. Killing the connection. Please update Android");
									return false;
								} catch (CertificateEncodingException e){
									callbackContext.error("Bad certificate encoding");
									return false;
								}
								return dumpHex(md.digest()).equals(removeSpaces(f_fingerprint.toUpperCase())); //Fingerprint check, in itself
							}
						});
					} catch (Exception e){
						callbackContext.error("Error while setting up the conneciton");
						return;
					}
					//Open connection and process request
					try {
						conn.connect();
					} catch (SocketTimeoutException e){
						callbackContext.error("Cannot connect to " + getUrlStr + " (timeout)");
						return;
					} catch (IOException e){
						callbackContext.error("Cannot connect to " + getUrlStr);
						return;
					}
					try {
						int httpStatusCode = conn.getResponseCode();
						Map<String, List<String>> responseHeaders = conn.getHeaderFields();
						BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
						String response = "";
						int c;
						while ((c = reader.read()) != -1){
							response += (char) c;
						}
						reader.close();
						conn.disconnect();

						JSONObject responseObj = buildResponseJson(httpStatusCode, response, responseHeaders);
						if (responseObj == null) callbackContext.error("Error while building response object");
						else callbackContext.success(responseObj);
					} catch (Exception e){
						callbackContext.error("Request failed");
					}
				}
			});
			return true;
		} else if (method.equals("req")){
			//Arbitrary HTTP request (any verb)
			cordova.getThreadPool().execute(new Runnable(){
				public void run(){
					JSONObject reqOptions;
					String fingerprint, hostname, port, path;
					try {
						reqOptions = new JSONObject(args.getString(0));
						fingerprint = args.getString(1);
						hostname = reqOptions.getString("host");
						port = reqOptions.getString("port");
						path = reqOptions.getString("path");
					} catch (JSONException e){
						callbackContext.error("Invalid parameters format");
						return;
					}
					String reqUrlStr = "https://" + hostname + ":" + port + path;
					URL reqUrl = initURL(reqUrlStr);
					HttpsURLConnection conn;
					try {
						conn = (HttpsURLConnection) reqUrl.openConnection();
					} catch (IOException e){
						callbackContext.error("Cannot connect to " + reqUrlStr);
						return;
					}

					//Append headers, if any
					if (reqOptions.has("headers")){
						JSONObject headers;
						try {
							headers = reqOptions.getJSONObject("headers");
						} catch (JSONException e){
							callbackContext.error("Invalid options.headers");
							return;
						}
						try {
							JSONArray headersNames = headers.names();
							for (int i = 0; i < headersNames.length(); i++){
								String currentHeaderName = headersNames.getString(i);
								conn.addRequestProperty(currentHeaderName, headers.getString(currentHeaderName));
							}
						} catch (Exception e){
							callbackContext.error("Error while appending headers to request");
							return;
						}
					}

					try {
						conn.setRequestMethod(reqOptions.getString("method"));
						conn.setUseCaches(false);
						final String f_hostname = hostname;
						final String f_fingerprint = fingerprint;
						conn.setDefaultHostnameVerifier(new HostnameVerifier(){
							public boolean verify(String connectedHostname, SSLSession sslSession){
								if (!connectedHostname.equals(f_hostname)){
									return false;
								}

								Certificate serverCert;
								MessageDigest md;
								try {
									serverCert = sslSession.getPeerCertificates()[0]; //Getting the servers own certificate
									md = MessageDigest.getInstance("SHA1"); //Instanciating SHA1
									md.update(serverCert.getEncoded());
								} catch (SSLPeerUnverifiedException e){
									callbackContext.error("Peer ceritifcate error. Cannot check identity. Kiling the connection");
									return false;
								} catch (NoSuchAlgorithmException e){
									callbackContext.error("Missing SHA1 support!. Killing the connection. Please update Android");
									return false;
								} catch (CertificateEncodingException e){
									callbackContext.error("Bad certificate encoding");
									return false;
								}
								return dumpHex(md.digest()).equals(removeSpaces(f_fingerprint.toUpperCase())); //Fingerprint check, in itself
							}
						});
					} catch (Exception e){
						callbackContext.error("Error while setting up the connection");
						return;
					}
					//Open connection and process request
					try {
						conn.connect();
					} catch (SocketTimeoutException e){
						callbackContext.error("Cannot connect to " + reqUrlStr + " (timeout)");
						return;
					} catch (IOException e){
						callbackContext.error("Cannot connect to " + reqUrlStr);
						return;
					}
					try {
						int httpStatusCode = conn.getResponseCode();
						Map<String, List<String>> responseHeaders = conn.getHeaderFields();
						BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
						String response = "";
						int c;
						while ((c = reader.read()) != -1){
							response += (char) c;
						}
						reader.close();
						conn.disconnect();

						JSONObject responseObj = buildResponseJson(httpStatusCode, response, responseHeaders);
						if (responseObj == null) callbackContext.error("Cannot build reponse");
						else callbackContext.success(responseObj);
					} catch (Exception e){
						callbackContext.error("Error while building response object");
					}
				}
			});
			return true;
		} else {
			callbackContext.error("Invalid method. Did you mean \"get()\" or \"req()\"?");
			return false;
		}
	}

	private static JSONObject buildResponseJson (final int responseCode, final String responseBody, Map<String, List<String>> responseHeaders){
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
				//Getting first values of header
				headersObj.put(currentHeader.getKey(), currentHeader.getValue().get(0));
			}
			responseObj.put("headers", headersObj);
		} catch (JSONException e){
			return null;
		}
		return responseObj;
	}

	private static String dumpHex(byte[] data){ //To hex. No spacing between bytes
		final int n = data.length;
		final StringBuilder sb = new StringBuilder(n * 2);
		for (int i = 0; i < n; i++){
			sb.append(HEX_CHARS[(data[i] >> 4) & 0x0f]);
			sb.append(HEX_CHARS[data[i] & 0x0f]);
		}
		return sb.toString();
	}

	private static String removeSpaces(String s){
		return s.replace(" ", "");
	}

	private static URL initURL(String s){
		try {
			return new URL(s);
		} catch (Exception e){
			return null;
		}
	}
}
