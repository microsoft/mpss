// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#import <UIKit/UIKit.h>

@interface MPSSAppDelegate : UIResponder <UIApplicationDelegate>
@end

@implementation MPSSAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
  (void)application;
  (void)launchOptions;
  return YES;
}

- (UISceneConfiguration *)application:(UIApplication *)application
    configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession
                                   options:(UISceneConnectionOptions *)options {
  (void)application;
  (void)connectingSceneSession;
  (void)options;
  return [[UISceneConfiguration alloc] initWithName:@"Default Configuration"
                                        sessionRole:UIWindowSceneSessionRoleApplication];
}

@end

@interface MPSSSceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation MPSSSceneDelegate

- (void)scene:(UIScene *)scene
    willConnectToSession:(UISceneSession *)session
                 options:(UISceneConnectionOptions *)options {
  (void)session;
  (void)options;
  if (![scene isKindOfClass:[UIWindowScene class]]) {
    return;
  }

  UIWindowScene *windowScene = (UIWindowScene *)scene;
  self.window = [[UIWindow alloc] initWithWindowScene:windowScene];
  UIViewController *controller = [[UIViewController alloc] init];
  controller.view.backgroundColor = [UIColor systemBackgroundColor];
  self.window.rootViewController = controller;
  [self.window makeKeyAndVisible];
}

@end

int main(int argc, char *argv[]) {
  @autoreleasepool {
    return UIApplicationMain(argc, argv, nil, NSStringFromClass([MPSSAppDelegate class]));
  }
}
