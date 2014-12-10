#import "PinnedHTTPS.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>

@interface CustomURLConnectionDelegate : NSObject<NSURLConnectionDelegate>

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSString *_fingerprint;
@property (nonatomic, assign) BOOL validFingerprint;
@property (retain) NSMutableData *_responseBody;
@property (retain) NSMutableDictionary *_responseObj;
@property (retain) NSString *_foundFingerprint;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId fingerprint:(NSString*)fingerprint;

@end

@implementation CustomURLConnectionDelegate

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId fingerprint:(NSString*)fingerprint
{
	self.validFingerprint = false;
	self._plugin = plugin;
	self._callbackId = callbackId;
	self._fingerprint = fingerprint;
	return self;
}

- (void)connection: (NSURLConnection*)connection willSendRequestForAuthenticationChallenge: (NSURLAuthenticationChallenge*)challenge
{
	NSLog(@"Cert check for %@ %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host);
    SecTrustRef serverCert = challenge.protectionSpace.serverTrust;
	NSString* connFingerprint = [self getFingerprint: SecTrustGetCertificateAtIndex(serverCert, 0)];
    self._foundFingerprint = connFingerprint;
    NSLog(@"Found fingerprint for %@ %@: %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host, connFingerprint);

	if ([connFingerprint caseInsensitiveCompare: self._fingerprint] == NSOrderedSame){
		self.validFingerprint = true;
		NSLog(@"Valid cert for %@ %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host);
		NSURLCredential *cred = [NSURLCredential credentialForTrust: serverCert];
		[[challenge sender] useCredential: cred forAuthenticationChallenge: challenge];
	} else {
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"INVALID_CERT"];
		[self._plugin writeJavascript:[rslt toErrorCallbackString: self._callbackId]];
		NSLog(@"Invalid cert for %@ %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host);
		[connection cancel];
	}
}

/*- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSLog(@"Cert check for %@ %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host);
    SecTrustRef serverCert = challenge.protectionSpace.serverTrust;
	NSString* connFingerprint = [self getFingerprint: SecTrustGetCertificateAtIndex(serverCert, 0)];
    self._foundFingerprint = connFingerprint;
    NSLog(@"Found fingerprint for %@ %@: %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host, connFingerprint);

    if ([self._foundFingerprint caseInsensitiveCompare:self._fingerprint] == NSOrderedSame){
        [challenge.sender useCredential:[NSURLCredential credentialForTrust:serverCert] forAuthenticationChallenge:challenge];
    } else {
        CDVPluginResult *rslt = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"INVALID_CERT"];
		[self._plugin writeJavascript:[rslt toErrorCallbackString: self._callbackId]];
		NSLog(@"Invalid cert for %@ %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host);
		[connection cancel];
    }
}*/

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    return [[protectionSpace authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust];
}

- (void)connection: (NSURLConnection*)connection didFailWithError: (NSError*)error {
	//[self._responseBody release];
	//[connection release];
    NSString *resultCode = @"Connection error. Details:";
	NSLog([NSString stringWithFormat:@"Connection error %@", [error localizedDescription]]);
    NSString *errStr = [NSString stringWithFormat:@"%@ %@", resultCode, [error localizedDescription]];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errStr];
    [self._plugin writeJavascript:[pluginResult toErrorCallbackString:self._callbackId]];
}

- (void)connection: (NSURLConnection*)connection didReceiveResponse:(NSURLResponse*)res{
    NSHTTPURLResponse *httpRes = (NSHTTPURLResponse*) res;
    self._responseObj = [NSMutableDictionary dictionaryWithDictionary:@{@"statusCode": [NSNumber numberWithLong:httpRes.statusCode], @"headers": httpRes.allHeaderFields}];
}

- (void)connection: (NSURLConnection*)connection didReceiveData:(NSData *)data{
	if (!self._responseBody) self._responseBody = [[NSMutableData alloc] initWithData: data];
	else [self._responseBody appendData: data];
}

- (void)connectionDidFinishLoading:(NSURLConnection*)connection {
	NSLog(@"End of response");
    //Append response body and pass to JS
    NSString *responseBodyStr = [[NSString alloc] initWithData: self._responseBody encoding: NSUTF8StringEncoding];
    [self._responseObj setValue: responseBodyStr forKey: @"body"];

    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:self._responseObj];
    [self._plugin writeJavascript: [pluginResult toSuccessCallbackString:self._callbackId]];
}

- (NSString*)getFingerprint: (SecCertificateRef) cert{
	NSData *certData = (__bridge NSData*) SecCertificateCopyData(cert);
	unsigned char sha1_bytes[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1(certData.bytes, (unsigned int) certData.length, sha1_bytes);
	NSMutableString *connFingerprint = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
	for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++){
		[connFingerprint appendFormat:@"%02x", sha1_bytes[i]];
	}
	return [connFingerprint lowercaseString];
}

@end

@interface PinnedHTTPS ()

@property (strong, nonatomic) NSString *_callbackId;

@end

@implementation PinnedHTTPS

- (void)get:(CDVInvokedUrlCommand*)command {
	NSString *reqUrl = [command.arguments objectAtIndex:0];
	NSString *expectedFingerprint = [command.arguments objectAtIndex:1];
    NSLog(@"get %@", reqUrl);
	NSURLRequest *req = [NSURLRequest requestWithURL: [NSURL URLWithString: reqUrl] cachePolicy: NSURLCacheStorageNotAllowed timeoutInterval: 20.0];
	CustomURLConnectionDelegate *delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin:self callbackId: command.callbackId fingerprint: expectedFingerprint];
    NSLog(@"Finger (get) : %@", delegate._fingerprint);

	NSURLConnection *connection = [[NSURLConnection alloc] initWithRequest: req delegate: delegate];
	if (!connection){
		NSLog(@"Error with connection");
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString: @"Connction error"];
		[self writeJavascript: [rslt toErrorCallbackString: command.callbackId]];
	}
}

- (void)req:(CDVInvokedUrlCommand*)command {
    NSString *optionsJsonStr = [command.arguments objectAtIndex:0];
    NSString *expectedFingerprint = [command.arguments objectAtIndex:1];
    NSLog(@"Finger: %@", expectedFingerprint);
    //Parsing the options dictionary
    NSData *jsonData = [optionsJsonStr dataUsingEncoding:NSUTF8StringEncoding];
    NSError *jsonErr;
    NSDictionary *options = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers|NSJSONReadingMutableLeaves error:&jsonErr];

    if (jsonErr != nil){
        CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_JSON_EXCEPTION messageAsString:@"invalid JSON for options object"];
        [self writeJavascript: [rslt toErrorCallbackString: command.callbackId]];
        return;
    }

    NSString *method = [options objectForKey:@"method"];
    if (!([method isEqual:@"get"] || [method isEqual:@"post"] || [method isEqual:@"delete"] || [method isEqual:@"put"] || [method isEqual:@"head"] || [method isEqual:@"options"] || [method isEqual:@"patch"] || [method isEqual:@"trace"] || [method isEqual:@"connect"])){
        CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString:@"Invalid HTTP method"];
        [self writeJavascript: [rslt toErrorCallbackString: command.callbackId]];
        return;
    }
    NSURL *reqUrl = [NSURL URLWithString: [NSString stringWithFormat:@"https://%@:%@%@", [options objectForKey:@"host"], [options objectForKey:@"port"], [options objectForKey:@"path"]]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:reqUrl cachePolicy: NSURLCacheStorageNotAllowed timeoutInterval: 20.0];
    req.HTTPMethod = [method uppercaseString];

    NSDictionary *headers = [options objectForKey:@"headers"];
    if (headers != nil){
        NSArray *headersList = headers.allKeys;
        NSUInteger i = 0;
        while (i < headersList.count){
            [req addValue: [headers objectForKey: [headersList objectAtIndex:i]] forHTTPHeaderField: [headersList objectAtIndex:i]];
            i++;
        }
    }

    //What to do with the request body?
    NSObject *reqBody = [options objectForKey:@"body"];
    if (reqBody != nil){
		if ([reqBody isKindOfClass: [NSString class]]){
			//Append to request and send out
			NSData *reqData = [(NSString*) reqBody dataUsingEncoding:NSUTF8StringEncoding];
			[req setValue:[NSString stringWithFormat:@"%d", (int) reqData.length] forHTTPHeaderField:@"Content-Length"];
			[req setHTTPBody: reqData];
		} else if ([reqBody isKindOfClass: [NSDictionary class]]){
			//To JSON, append to request and send out
			NSError *stringifyErr = nil;
			NSData *reqData = [NSJSONSerialization dataWithJSONObject: (NSDictionary*) reqBody options:NSJSONWritingPrettyPrinted error:&stringifyErr];
			[req setValue: [NSString stringWithFormat:@"%d", (int) reqData.length] forHTTPHeaderField:@"Content-Length"];
			[req setValue: @"application/json" forHTTPHeaderField:@"Content-Type"];
			[req setHTTPBody: reqData];
		} else {
			NSLog(@"Unknown body type");
			CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_JSON_EXCEPTION messageAsString:@"Invalid request body format"];
			[self writeJavascript: [rslt toErrorCallbackString:command.callbackId]];
			return;
		}
    }

    CustomURLConnectionDelegate* delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin: self callbackId: command.callbackId fingerprint: expectedFingerprint];
    NSURLConnection *connection = [[NSURLConnection alloc] initWithRequest: req delegate: delegate];

    if(!connection){
		NSLog(@"Connection couldn't be initialized");
        CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString:@"Connection error"];
        [self writeJavascript: [rslt toErrorCallbackString: command.callbackId]];
    }
}

/*- (NSString*) getMultipart: (NSDictionary)d{
    NSMutableString *resultStr =
}*/

@end
