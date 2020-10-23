#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RNArgon2, NSObject)

RCT_EXTERN_METHOD(argon2: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

@end
