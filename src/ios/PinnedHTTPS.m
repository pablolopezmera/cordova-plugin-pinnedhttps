#import "PinnedHTTPS.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>

@interface CustomURLConnectionDelegate : NSObject<NSURLConnectionDelegate>

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSString *_fingerprint;
@property (strong, nonatomic) NSDictionary *_requestHeaders;
@property (strong, nonatomic) NSDictionary *_requestBody;
@property (nonatomic, assign) BOOL validFingerprint;
@property (nonatomic, assign) NSString *_responseBody;
@property (nonatomic, assign) NSDictionary *_responseHeaders;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId fingerprint:(NSString*)fingerprint;

@end

@implmentation CustomURLConnectionDelegate

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId fingerprint:(NSString*)fingerprint
{
	self.validFingerprint = false;
	self._plugin = plugin;
	self._callbackId = callbackId;
	self._fingerprint = fingerprint;
	return self;
}

- (void)connection: (NSURLConnection*)connection willSendRequestForAuthenticationChallenge: (NSURLAuthenticationChallenge*)challange
{
	NSString* connFingerprint = [self getFingerprint: SecTrustGetCertificateAtIndex(challenge.protectionSpace.serverTrust, 0)];

	if ([connFingerprint caseInsensitiveCompare: self._fingerprint] == NSOrderedSame){
		self.validFingerprint = true;
	} else {
		CDVPluginResult* rslt = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsStr:@"Invalid fingerprint on server!"];
		[self._plugin writeJavascript:[rslt toErrorCallbackString: self._callbackId]];
	}
}

- (void)connection: (NSURLConnection*)connection didFailWithError: (NSError*)error {
	NSString *resultCode = @"Connection error. Details:";
    NSString *errStr = [NSString stringWithFormat:@"%@ %@", resultCode, [error localizedDescription]];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errStr];
    [self._plugin writeJavascript:[pluginResult toErrorCallbackString:self._callbackId]];
}

- (void)connection: (NSURLConnection*)connection didRecieveResponse:(NSURLResponse*)res{
	
}

- (void)connection: (NSURLConnection*)connection didReceiveData:(NSData *)data{

}

- (void)connectionDidFinishLoading:(NSURLConnection*)connection {

}

- (NSString*)getFingerprint: (SecCertificateRef) cert{
	NSData* certData = (__bridge NSData*) SecCertificateCopyData(cert);
	unsigned char sha1_bytes[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1(certData.bytes, certData.length, sha1_bytes);
	NSMutableString* connFingerprint = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
	for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++){
		[connFingerprint appendFormat:@"%x", sha1_bytes[i]];
	}
	return [connFingerprint lowercaseString];
}

@end

@interface PinnedHTTPS ()

@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSMutableData *_connections;

@end

@implementation PinnedHTTPS

- (void)get:(CDVInvokedUrlCommand*)command {
	NSString* reqUrl = [command.arguments objectAtIndex:0];
	NSString* expectedFingerprint = [command.arguments objectAtIndex:1];

	NSURLRequest* req = [NSURLRequest requestWithURL: [NSURL URLWithString: reqUrl]];
	CustomURLConnectionDelegate delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin: self callback: command.callbackId fingerprint: expectedFingerprint];

	NSMutableData *receivedData;

	NSURLConnection *connection = [NSURLConnection connectionWithRequest: req delegate: delegate];
	if (!connection){
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString: @"Connction error"];
		[self writeJavascript: [rslt toErrorCallbackString: command.callbackId]];
		return;
	} else {
		receivedData = [[NSMutableData alloc] init];
	}


}

- (void)req:(CDVInvokedUrlCommand*)command {

}

@end
