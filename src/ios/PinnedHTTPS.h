#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface PinnedHTTPS : CDVPlugin

- (void)get:(CDVInvokedUrlCommand*)command;
- (void)req:(CDVInvokedUrlCommand*)command;

@end
