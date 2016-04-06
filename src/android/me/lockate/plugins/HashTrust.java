package me.lockate.plugins;

import android.util.Log;

import java.lang.IllegalArgumentException;
import java.util.*;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class HashTrust implements X509TrustManager {

	private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	private final static String logTag = "PinnedHTTPS";

	private List<String> _expectedFingerprints;
	private String _fingerprintType = "SHA1";

	public HashTrust(List<String> fingerprints, String fingerprintType){
		//Checking fingerprints argument
		if (fingerprints == null || fingerprints.size() == 0) throw new IllegalArgumentException("Excepted fingerprints list cannot be null");
		for (int i = 0; i < fingerprints.size(); i++){
			fingerprints.set(i, removeSpaces(fingerprints.get(i)));
		}
		_expectedFingerprints = fingerprints;
		//Checking the fingerprintType argument
		if (fingerprintType == null || fingerprintType.length() == 0) return; //Accept null or empty strings. Using SHA1 default
		if (!(fingerprintType.equals("SHA1") || fingerprintType.equals("SHA256"))) throw new IllegalArgumentException("When defined, fingerprintType must either be SHA1 or SHA256");
		_fingerprintType = fingerprintType;
	}

	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException{
		if (chain == null){
			throw new IllegalArgumentException("Cert chain cannot be null");
		}

		if (!(chain.length > 0)){
			throw new IllegalArgumentException("Cert chain cannot be empty");
		}

		String foundFingerprint;
		boolean isValid = false;

		for (int iCert = 0; iCert < chain.length; iCert++){
			X509Certificate serverCert = chain[iCert];
			//Instanciating SHA digest
			MessageDigest md;
			try {
				md = MessageDigest.getInstance(_fingerprintType);
				md.update(serverCert.getEncoded());
			} catch (NoSuchAlgorithmException e){
				throw new CertificateException("Missing SHA1 support! Killing the connection");
			} catch (CertificateEncodingException e){
				throw new CertificateException("Bad certificate encoding");
			}
			//Getting the fingerprint of the current cert
			foundFingerprint = dumpHex(md.digest());
			Log.v(logTag, "Found fingerprint at index " + iCert + ":\t" + foundFingerprint);
			for (int i = 0; i < _expectedFingerprints.size(); i++){
				if (foundFingerprint.equalsIgnoreCase(_expectedFingerprints.get(i))){
					isValid = true;
					break;
				}
			}
			if (isValid) break; //Get out of the loop if the chain has been validated
		}

		if (!isValid) throw new CertificateException("INVALID_CERT");
	}

	public void checkClientTrusted(X509Certificate[] chain, String authType){

	}

	public X509Certificate[] getAcceptedIssuers(){
		return null;
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
