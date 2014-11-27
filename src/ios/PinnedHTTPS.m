#import "PinnedHTTPS.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>

@interface CustomURLConnectionDelegate : NSObject<NSURLConnectionDelegate>

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSString *_fingerprint;
@property (strong, nonatomic) NSDictionary *_requestHeaders;
@property (strong, nonatomic) NSMutableData *_requestBody;
@property (nonatomic, assign) BOOL validFingerprint;
@property (nonatomic, assign) NSMutableData *_responseBody;
@property (nonatomic, assign) NSMutableDictionary *_responseObj;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId fingerprint:(NSString*)fingerprint;

@end

@implementation CustomURLConnectionDelegate

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId fingerprint:(NSString*)fingerprint
{
	self.validFingerprint = false;
	self._plugin = plugin;
	self._callbackId = callbackId;
	self._fingerprint = fingerprint;
	self._responseBody = [[NSMutableData alloc] init];
	return self;
}

- (void)connection: (NSURLConnection*)connection willSendRequestForAuthenticationChallenge: (NSURLAuthenticationChallenge*)challenge
{
	NSString* connFingerprint = [self getFingerprint: SecTrustGetCertificateAtIndex(challenge.protectionSpace.serverTrust, 0)];

	if ([connFingerprint caseInsensitiveCompare: self._fingerprint] == NSOrderedSame){
		self.validFingerprint = true;
	} else {
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Invalid fingerprint on server!"];
		[self._plugin writeJavascript:[rslt toErrorCallbackString: self._callbackId]];
	}
}

- (void)connection: (NSURLConnection*)connection didFailWithError: (NSError*)error {
	//[self._responseBody release];
	//[connection release];
    NSString *resultCode = @"Connection error. Details:";
    NSString *errStr = [NSString stringWithFormat:@"%@ %@", resultCode, [error localizedDescription]];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errStr];
    [self._plugin writeJavascript:[pluginResult toErrorCallbackString:self._callbackId]];
}

- (void)connection: (NSURLConnection*)connection didRecieveResponse:(NSURLResponse*)res{
    NSHTTPURLResponse *httpRes = (NSHTTPURLResponse*) res;
    self._responseObj = [NSMutableDictionary initWithDictionary:@{@"statusCode": [NSNumber numberWithInt:httpRes.statusCode, @"headers": httpRes.allHeaderFields}];
}

- (void)connection: (NSURLConnection*)connection didReceiveData:(NSData *)data{
	[self._responseBody appendData: data];
}

- (void)connectionDidFinishLoading:(NSURLConnection*)connection {
    //Append response body and pass to JS
    NSString *responseBodyStr = [[NSString alloc] initWithData: self._responseBody encoding: NSUTF8StringEncoding];
    [self._responseObj setObject: responseBodyStr forKey: @"body"];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary: self._responseObj];
    [self._plugin writeJavascript: [pluginResult toSuccessCallbackString:self._callbackId]];
    //[responseBodyStr release];
}

- (NSString*)getFingerprint: (SecCertificateRef) cert{
	NSData *certData = (__bridge NSData*) SecCertificateCopyData(cert);
	unsigned char sha1_bytes[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1(certData.bytes, certData.length, sha1_bytes);
	NSMutableString *connFingerprint = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
	for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++){
		[connFingerprint appendFormat:@"%x", sha1_bytes[i]];
	}
	return [connFingerprint lowercaseString];
}

@end

@interface PinnedHTTPS ()

@property (strong, nonatomic) NSString *_callbackId;
//@property (strong, nonatomic) NSMutableData *_connections;

@end

@implementation PinnedHTTPS

- (void)get:(CDVInvokedUrlCommand*)command {
	NSString *reqUrl = [command.arguments objectAtIndex:0];
	NSString *expectedFingerprint = [command.arguments objectAtIndex:1];

	NSURLRequest *req = [NSURLRequest requestWithURL: [NSURL URLWithString: reqUrl] cachePolicy: NSURLCacheStorageNotAllowed timeoutInterval: 20.0];
	CustomURLConnectionDelegate *delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin:self callback: command.callbackId fingerprint: expectedFingerprint];

	NSURLConnection *connection = [NSURLConnection connectionWithRequest: req delegate: delegate];
	if (!connection){
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString: @"Connction error"];
		[self writeJavascript: [rslt toErrorCallbackString: command.callbackId]];
	}
}

- (void)req:(CDVInvokedUrlCommand*)command {
    NSString *optionsJsonStr = [command.arguments objectAtIndex:0];
    NSString *expectedFingerprint = [command.arguments objectAtIndex:1];
    //Parsing the options dictionary
    NSData *jsonData = [optionsJsonStr dataUsingEncoding:NSUTF8StringEncoding];
    NSError *jsonErr = nil;
    NSDictionary *options = [NSJSONSerialization JSONObjectWithData:jsonData options:nil error:&jsonErr];

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
			[req setValue:[NSString stringWithFormat:@"%d", reqData.length] forHTTPHeaderField:@"Content-Length"];
			[req setHTTPBody: reqData];
		} else if ([reqBody isKindOfClass: [NSDictionary class]]){
			//To JSON, append to request and send out
			NSError *stringifyErr = nil;
			NSData *reqData = [NSJSONSerialization dataWithJSONObject: (NSDictionary*) reqBody options:nil error:&stringifyErr];
			[req setValue: [NSString stringWithFormat:@"%d", reqData.length] forHTTPHeaderField:@"Content-Length"];
			[req setValue: @"application/json" forHTTPHeaderField:@"Content-Type"];
			[req setHTTPBody: reqData];
		} else {
			CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_JSON_EXCEPTION messageAsString:@"Invalid request body format"];
			[self writeJavascript: [rslt toErrorCallbackString:command.callbackId]];
			return;
		}
    }

    CustomURLConnectionDelegate* delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin: self callback: command.callbackId fingerprint: expectedFingerprint];
    NSURLConnection *connection = [[NSURLConnection alloc] connectionWithRequest: req delegate: delegate];

    if(!connection){
        CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString:@"Connection error"];
        [self writeJavascript: [rslt toErrorCallbackString: command.callbackId]];
    }
}

/*- (NSString*) getMultipart: (NSDictionary)d{
    NSMutableString *resultStr =
}*/

@end
