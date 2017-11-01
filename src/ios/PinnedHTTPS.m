#import "PinnedHTTPS.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>

@interface CustomURLConnectionDelegate : NSObject<NSURLConnectionDelegate>

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSArray *_fingerprints;
@property (nonatomic, assign) BOOL returnBuffer;
@property (nonatomic, assign) BOOL validFingerprint;
@property (retain) NSMutableData *_responseBody;
@property (retain) NSMutableDictionary *_responseObj;
@property (retain) NSString *_foundFingerprint;
@property (retain) NSString *_fingerprintType;
@property (retain) NSString *_allFingerprints;
@property (retain) NSString *log;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId fingerprints:(NSArray*)fingerprints fingerprintType:(NSString*)fingerprintType;

@end

@implementation CustomURLConnectionDelegate

-(void)WriteToStringFile:(NSString *)textToWrite{
    NSFileManager *fileMgr;
    NSString *homeDir;
    fileMgr = [NSFileManager defaultManager];
    homeDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    
    NSString *filepath;
    filepath = [[NSString alloc] init];
    NSError *err;
    
    filepath = [homeDir stringByAppendingPathComponent:@"pinnedhttps.log"];
    
    BOOL ok = [textToWrite writeToFile:filepath atomically:YES encoding:NSUnicodeStringEncoding error:&err];
    
    if (ok) {
        NSLog(@"File writen %@\n%@",
              filepath, textToWrite);
    } else {
        NSLog(@"Error writing sfile at %@\n%@",
              filepath, [err localizedFailureReason]);
    }
    
}

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId fingerprints:(NSArray*)fingerprints fingerprintType:(NSString*)fingerprintType
{
	self.validFingerprint = false;
	self.returnBuffer = false;
	self._plugin = plugin;
	self._callbackId = callbackId;
	self._fingerprints = fingerprints;
	self._fingerprintType = fingerprintType;
	return self;
}

- (void)connection: (NSURLConnection*)connection willSendRequestForAuthenticationChallenge: (NSURLAuthenticationChallenge*)challenge
{
	//NSLog(@"Cert check for %@ %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host);
    SecTrustRef serverCert = challenge.protectionSpace.serverTrust;

	NSString* connFingerprint;
	bool isValid = false;
	int certCount = SecTrustGetCertificateCount(serverCert);
    
    self._allFingerprints = @"";
    self.log = @"Start fingerprint validation...";
    
    printf("\nFound fingerprint size: %lu", (unsigned long)certCount);
    self.log = [self.log stringByAppendingString:[NSString stringWithFormat:@"\nFound fingerprint size: %lu", (unsigned long)certCount]];
    
    printf("\nAuthorized fingerprint size: %lu", (unsigned long)self._fingerprints.count);
	self.log = [self.log stringByAppendingString:[NSString stringWithFormat:@"\nAuthorized fingerprint size: %lu", (unsigned long)self._fingerprints.count]];
    
    for (int i = 0; i < certCount; i++){
		if ([self._fingerprintType isEqual: @"SHA1"]) connFingerprint = [self getSHA1Fingerprint: SecTrustGetCertificateAtIndex(serverCert, i)];
		else connFingerprint = [self getSHA256Fingerprint: SecTrustGetCertificateAtIndex(serverCert, i)];
        
        printf("\n Found fingerprint: %s", [connFingerprint UTF8String]);
        self.log = [self.log stringByAppendingString:[NSString stringWithFormat:@"\n Found fingerprint: %s", [connFingerprint UTF8String]]];

        printf("\n Compare with:");
        self.log = [self.log stringByAppendingString:[NSString stringWithFormat:@"\n Compare with:"]];

        self._allFingerprints = [self._allFingerprints stringByAppendingString:connFingerprint];
        self._allFingerprints = [self._allFingerprints stringByAppendingString:@","];
        
        for (int j = 0; j < self._fingerprints.count; j++){
            
            printf("\n   %s", [[self._fingerprints objectAtIndex: j] UTF8String] );
            self.log = [self.log stringByAppendingString:[NSString stringWithFormat:@"\n   %s", [[self._fingerprints objectAtIndex: j] UTF8String]]];

            
            if ([connFingerprint caseInsensitiveCompare: [self._fingerprints objectAtIndex: j]] == NSOrderedSame){
                self.log = [self.log stringByAppendingString:[NSString stringWithFormat:@"\n     fingerprint matched: %s=%s", [connFingerprint UTF8String], [[self._fingerprints objectAtIndex: j] UTF8String]]];
				isValid = true;
				break;
			}
		}
		if (isValid) break;
	}
    printf("\n");
    
    self._foundFingerprint = connFingerprint;
    //NSLog(@"Found fingerprint for %@ %@: %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host, connFingerprint);

	if (isValid){
        self.log = [self.log stringByAppendingString:[NSString stringWithFormat:@"\nisvalid is true"]];
		self.validFingerprint = true;
		//NSLog(@"Valid cert for %@ %@", connection.originalRequest.HTTPMethod, connection.originalRequest.URL.host);
		NSURLCredential *cred = [NSURLCredential credentialForTrust: serverCert];
		[[challenge sender] useCredential: cred forAuthenticationChallenge: challenge];
	} else {
        self.log = [self.log stringByAppendingString:[NSString stringWithFormat:@"\nisvalid is false, should return error"]];
        NSDictionary *jsonObj = [ [NSDictionary alloc]
                                 initWithObjectsAndKeys :
                                 @"INVALID_CERT", @"error",
                                 @"false", @"success",
                                 self._allFingerprints, @"all_fingerprints",
                                 nil
                                 ];
        
        CDVPluginResult *rslt = [ CDVPluginResult
                                         resultWithStatus    : CDVCommandStatus_ERROR
                                         messageAsDictionary : jsonObj
                                         ];
        
        printf("self.log error");
        printf("\n%s", [self.log UTF8String]);
        [self WriteToStringFile : self.log];

		// CDVPluginResult *rslt = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"INVALID_CERT"];
        
		[self._plugin.commandDelegate sendPluginResult: rslt callbackId: self._callbackId];
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

- (NSCachedURLResponse*)connection: (NSURLConnection*)connection willCacheResponse: (NSCachedURLResponse*)cachedResponse
{
	return nil;
}

- (void)connection: (NSURLConnection*)connection didFailWithError: (NSError*)error {
	//[self._responseBody release];
	//[connection release];
    NSString *resultCode = @"Connection error. Details:";
	NSLog([NSString stringWithFormat:@"Connection error %@", [error localizedDescription]]);
    NSString *errStr;
	CDVPluginResult *pluginResult;

	if ([error.domain caseInsensitiveCompare:@"NSURLErrorDomain"] == NSOrderedSame){
		if (error.code == NSURLErrorTimedOut){
			errStr = @"TIMEOUT";
		} else if (error.code == NSURLErrorBadURL || error.code == NSURLErrorUnsupportedURL){
			errStr = @"INVALID_URL";
		} else {
			errStr = @"CANT_CONNECT";
		}
	} else {
		errStr = [NSString stringWithFormat:@"%@ %@", resultCode, [error localizedDescription]];
	}

	pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errStr];
    [self._plugin.commandDelegate sendPluginResult: pluginResult callbackId: self._callbackId];
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
	//NSLog(@"End of response");
    //Append response body and pass to JS
	if (self.returnBuffer == false){
		NSString *responseBodyStr = [[NSString alloc] initWithData: self._responseBody encoding: NSUTF8StringEncoding];
	    [self._responseObj setValue: responseBodyStr forKey: @"body"];
	} else {
		NSMutableArray *responseBodyArray = [[NSMutableArray alloc] initWithCapacity: self._responseBody.length];
		for (int i = 0; i < self._responseBody.length; i++){
			unsigned char currentByte;
			NSRange currentByteRange = NSMakeRange(i, sizeof(currentByte));
			[self._responseBody getBytes:&currentByte range: currentByteRange];
			[responseBodyArray addObject: [NSNumber numberWithUnsignedChar: currentByte]];
		}

		NSArray *responseBodyData = [[NSArray alloc] initWithArray: responseBodyArray];
		[self._responseObj setValue: responseBodyData forKey: @"body"];
	}

//    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:self._responseObj];
    
    NSDictionary *jsonObj = [ [NSDictionary alloc]
                             initWithObjectsAndKeys :
                             @"true", @"success",
                             self._foundFingerprint, @"validated_fingerprint",
                             self._allFingerprints, @"all_fingerprints",
                             nil
                             ];
    
    printf("self.log ok\n");
    printf("%s", [self.log UTF8String]);
    self.log = [self.log stringByAppendingString:[NSString stringWithFormat:@"\nBefore return OK"]];
    [self WriteToStringFile : self.log];
    
    CDVPluginResult *pluginResult = [ CDVPluginResult
                                     resultWithStatus    : CDVCommandStatus_OK
                                     messageAsDictionary : jsonObj
                                     ];
    
    [self._plugin.commandDelegate sendPluginResult: pluginResult callbackId: self._callbackId];
}

- (NSString*)getSHA1Fingerprint: (SecCertificateRef) cert{
	NSData *certData = (__bridge NSData*) SecCertificateCopyData(cert);
	unsigned char sha1_bytes[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1(certData.bytes, (unsigned int) certData.length, sha1_bytes);
	NSMutableString *connFingerprint = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
	for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++){
		[connFingerprint appendFormat:@"%02x", sha1_bytes[i]];
	}
	return [connFingerprint lowercaseString];
}

- (NSString*)getSHA256Fingerprint: (SecCertificateRef) cert{
	NSData *certData = (__bridge NSData*) SecCertificateCopyData(cert);
	unsigned char sha256_bytes[CC_SHA256_DIGEST_LENGTH];
	CC_SHA256(certData.bytes, (unsigned int) certData.length, sha256_bytes);
	NSMutableString *connFingerprint = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
	for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++){
		[connFingerprint appendFormat:@"%02x", sha256_bytes[i]];
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
	NSString *expectedFingerprintsStr = [command.arguments objectAtIndex:1];
	NSString *fingerprintTypeStr = @"SHA1";
	//Check whether a fingerprintTypeStr argument has been provided; check its value
	if ([command.arguments count] > 2){
		fingerprintTypeStr = [command.arguments objectAtIndex: 2];
	}
	if (!([fingerprintTypeStr isEqual: @"SHA1"] || [fingerprintTypeStr isEqual: @"SHA256"])){
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString: @"INVALID_FINGERPRINT_TYPE"];
		[self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
		return;
	}
	//Parsing the expected fingerprints list
	NSData *fingerprintsJsonData = [expectedFingerprintsStr dataUsingEncoding:NSUTF8StringEncoding];
	NSError *fingerprintsJsonErr;
	id expectedFingerprintsPt = [NSJSONSerialization JSONObjectWithData:fingerprintsJsonData options:NSJSONReadingMutableContainers|NSJSONReadingMutableLeaves error:&fingerprintsJsonErr];

	if (fingerprintsJsonErr != nil || ![expectedFingerprintsPt isKindOfClass: [NSArray class]]){
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_JSON_EXCEPTION messageAsString:@"INVALID_PARAMS"];
		[self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
		return;
	}

	NSArray *expectedFingerprints = expectedFingerprintsPt;

    //NSLog(@"get %@", reqUrl);
	NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL: [NSURL URLWithString: reqUrl] cachePolicy: NSURLRequestReloadIgnoringCacheData timeoutInterval: 20.0];
	[req setValue: @"close" forHTTPHeaderField: @"Connection"];
	[req setValue: @"utf-8" forHTTPHeaderField: @"Accept-Charset"];
	CustomURLConnectionDelegate *delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin:self callbackId: command.callbackId fingerprints: expectedFingerprints fingerprintType: fingerprintTypeStr];
    //NSLog(@"Finger (get) : %@", expectedFingerprintsStr);

	NSURLConnection *connection = [[NSURLConnection alloc] initWithRequest: req delegate: delegate];
	if (!connection){
		NSLog(@"Error with connection");
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString: @"CANT_CONNECT"];
		[self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
	}
}

- (void)req:(CDVInvokedUrlCommand*)command {
    NSString *optionsJsonStr = [command.arguments objectAtIndex:0];
    NSString *expectedFingerprintsStr = [command.arguments objectAtIndex:1];
	NSString *fingerprintTypeStr = @"SHA1";
	//Check whether a fingerprintTypeStr has been provided; check its value
	if ([command.arguments count] > 2){
		fingerprintTypeStr = [command.arguments objectAtIndex: 2];
	}
	if (!([fingerprintTypeStr isEqual: @"SHA1"] || [fingerprintTypeStr isEqual: @"SHA256"])){
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString: @"INVALID_FINGERPRINT_TYPE"];
		[self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
		return;
	}
	//NSLog(@"Finger: %@", expectedFingerprintsStr);
    //Parsing the options dictionary
    NSData *jsonData = [optionsJsonStr dataUsingEncoding:NSUTF8StringEncoding];
    NSError *jsonErr;
    NSDictionary *options = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers|NSJSONReadingMutableLeaves error:&jsonErr];

    if (jsonErr != nil){
        CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_JSON_EXCEPTION messageAsString:@"INVALID_PARAMS"];
        [self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
        return;
    }

	//Parsing the expected fingerprints list
	NSData *fingerprintsJsonData = [expectedFingerprintsStr dataUsingEncoding:NSUTF8StringEncoding];
	NSError *fingerprintsJsonErr;
	id expectedFingerprintsPt = [NSJSONSerialization JSONObjectWithData:fingerprintsJsonData options:NSJSONReadingMutableContainers|NSJSONReadingMutableLeaves error:&fingerprintsJsonErr];

	if (fingerprintsJsonErr != nil || ![expectedFingerprintsPt isKindOfClass: [NSArray class]]){
		CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_JSON_EXCEPTION messageAsString:@"INVALID_PARAMS"];
		[self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
		return;
	}

	NSArray *expectedFingerprints = expectedFingerprintsPt;

    NSString *method = [options objectForKey:@"method"];
    if (!([method isEqual:@"get"] || [method isEqual:@"post"] || [method isEqual:@"delete"] || [method isEqual:@"put"] || [method isEqual:@"head"] || [method isEqual:@"options"] || [method isEqual:@"patch"] || [method isEqual:@"trace"] || [method isEqual:@"connect"])){
        CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString:@"INVALID_METHOD"];
        [self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
        return;
    }
    NSURL *reqUrl = [NSURL URLWithString: [NSString stringWithFormat:@"https://%@:%@%@", [options objectForKey:@"host"], [options objectForKey:@"port"], [options objectForKey:@"path"]]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:reqUrl cachePolicy: NSURLRequestReloadIgnoringCacheData timeoutInterval: 20.0];
    req.HTTPMethod = [method uppercaseString];
	[req setValue: @"close" forHTTPHeaderField: @"Connection"];
	[req setValue: @"utf-8" forHTTPHeaderField: @"Accept-Charset"];
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

			if (stringifyErr != nil){
				CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_JSON_EXCEPTION messageAsString:@"INVALID_BODY"];
				[self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
				return;
			}

			[req setValue: [NSString stringWithFormat:@"%d", (int) reqData.length] forHTTPHeaderField:@"Content-Length"];
			[req setValue: @"application/json" forHTTPHeaderField:@"Content-Type"];
			[req setHTTPBody: reqData];
		} else {
			NSLog(@"Unknown body type");
			CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_JSON_EXCEPTION messageAsString:@"INVALID_BODY"];
			[self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
			return;
		}
    }

    CustomURLConnectionDelegate* delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin: self callbackId: command.callbackId fingerprints: expectedFingerprints fingerprintType: fingerprintTypeStr];
	NSObject *returnBuffer = [options objectForKey: @"returnBuffer"];
	if (returnBuffer != nil) delegate.returnBuffer = true;

    NSURLConnection *connection = [[NSURLConnection alloc] initWithRequest: req delegate: delegate];

    if(!connection){
		NSLog(@"Connection couldn't be initialized");
        CDVPluginResult *rslt = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString:@"CANT_CONNECT"];
        [self.commandDelegate sendPluginResult: rslt callbackId: command.callbackId];
    }
}

/*- (NSString*) getMultipart: (NSDictionary)d{
    NSMutableString *resultStr =
}*/


@end
