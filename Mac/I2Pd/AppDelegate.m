//
//  AppDelegate.m
//  I2Pd
//
//  Created by Mikal Villa on 29/03/16.
//  Copyright © 2016 Purple I2P. All rights reserved.
//

#import "AppDelegate.h"

@interface AppDelegate ()

@property (strong, nonatomic) NSStatusItem *statusItem;

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    [self setupStatusItem];
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
}

- (void)setupStatusItem {
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    self.statusItem.button.image = [NSImage imageNamed:@"menuBarIcon"];
    
    [self updateStatusItemMenu];
}

- (void)updateStatusItemMenu {
    NSMenu *menu = [[NSMenu alloc] init];
    [menu addItemWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@""];
    self.statusItem.menu = menu;
}

#pragma mark - Menu actions

- (void)openWebConsole:(id)sender
{
    NSURL *URL = [NSURL URLWithString:@"http://127.0.0.1:7070"];
    [[NSWorkspace sharedWorkspace] openURL:URL];
}


@end
