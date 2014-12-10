package me.lockate.plugins;

import java.lang.IllegalArgumentException;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class HashTrust implements X509TrustManager {

	//private String expPublicKey;

	public HashTrust(){

	}

	/*public HashTrust(String expectedPublicKey){
		//if (expectedPublicKey != null) expPublicKey = expectedPublicKey;
	}*/

	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException{
		if (chain == null){
			throw new IllegalArgumentException("Cert chain cannot be null");
		}

		if (!(chain.length > 0)){
			throw new IllegalArgumentException("Cert chain cannot be empty");
		}

		/*TrustManagerFactory tmf;
		try {
			tmf = TrustManagerFactory.getInstance("X509");
			tmf.init((KeyStore) null);

			for (TrustManager trustManager: tmf.getTrustManagers()){
				((X509TrustManager) trustManager).checkServerTrusted(chain, authType);
			}
		} catch (Exception e){
			throw new CertificateException(e);
		}*/

		//NOT DOING ANYTHING HERE. DO NOT CHECK THE PUBLIC KEY
		//We suppose that the fingerprint check is enough for now.
		//Hence, we do not check the certificate chain
	}

	public void checkClientTrusted(X509Certificate[] chain, String authType){

	}

	public X509Certificate[] getAcceptedIssuers(){
		return null;
	}

}
