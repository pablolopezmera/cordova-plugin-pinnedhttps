package me.lockate.plugins;

import org.json.Array;
import org.json.JSONException;

import java.util.Map;
import java.util.List;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.cert.CertificateException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

public class PinnedHTTP extends CordovaPlugin {

	private static char[] HEX_CHARS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];

	@Override
	public boolean execute(final String method, final JSONArray args, final CallbackContext callbackContext) throws JSONException, IOException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {
		if (method.equals("get")){
			//Standard HTTPS GET request. Running in a new thread
			cordova.getThreadPool().execute(new Runnable(){
				public void run(){
					final String getUrlStr = args.getString(0); //Request URL
					final String fingerprint = args.getString(1); //Expected fingerprint
					final URL getUrl = new URL(getUrlStr);
					final String hostname = getUrl.getHost(); //Getting hostname from URL
					HttpsURLConnection conn = new HttpsURLConnection(new URL(getUrl));
					//Setting up the fingerprint verification upon session negotiation
					conn.setUseCaches(false);
					conn.setDefaultHostnameVerifier(new HostnameVerifier(){
						public boolean verify(String connectedHostname, SSLSession sslSession){
							if (!connectedHostname.equals(hostname)){
								return false;
							}
							final Certificate serverCert = sslSession.getPeerCertificates()[0]; //Getting the servers own certificate
							final MessageDigest md = MessageDigest.getInstance('SHA1'); //Instanciating SHA1
							md.update(serverCert.getEncoded());
							return dumpHex(md.digest()).equals(removeSpaces(fingerprint.toUpperCase())); //Fingerprint check, in itself
						}
					});
					//Open connection and process request
					conn.connect();
					int httpStatusCode = conn.getResponseCode();
					Map<String, List<String>> responseHeaders = conn.getHeaderFields();
					BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
					String reponse = "";
					int c;
					while ((c = reader.read()) != -1){
						response += (char) c;
					}
					reader.close();
					conn.disconnect();
				}
			});
		} else if (method.equals("req")){
			//Arbitrary HTTP request (any verb)
		} else {

		}
	}

	/*private static boolean CheckFingerprint (HttpsUrlConnection conn, final String fingerprint) throws IOException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {

	}*/

	private static String buildResponseJson (final int responseCode, final String responseBody, Map<String, List<String>> responseHeaders) throws JSONException {

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
}
