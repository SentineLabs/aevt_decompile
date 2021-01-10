//
//  main.m
//  aevt_decompile
//
//  Created by Phil Stokes on 19/12/2020.
//  SentinelOne, SentinelLabs
//  https://labs.sentinelone.com
//

//
// This is a work-in-progress command line tool that will help parse the output
// of applescript-disassembler.py into something more human-readable.
//
// Because of the dearth of run-only AS samples, this code will undoubtedly need revision
// in light of further samples.

// Workflow:

//      disassembler.py <run-only script> > output.txt
//      aevt_decompile output.txt
//         -> By default output is written to ~/Desktop/output.out.
//      ****  Bear in mind macOS restrictions on code writing to ~/Desktop, so change as preferred; ****

//
// Full write up on usage and malware analysis:
//     https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts
//

#import <Foundation/Foundation.h>

NSArray  * ae_frameworks(void);
NSString * aevt_divide(NSString * hexStr);
NSString * aevt_group(NSString * codeStr);
NSString * decode(NSString * hex, int d);
NSString * hexfunc(NSString * hex);
NSString * human_readable_code(NSString * searchStr);
NSString * locateAppSDEF(NSString *str);


int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc == 2) {
            
            NSError * error = nil;
            NSURL * path = [NSURL fileURLWithPath:@(argv[1])];
            NSString * contents = [NSString stringWithContentsOfURL:path encoding:NSUTF8StringEncoding error:&error];
            NSString * funcParam; // Hold function paramaters;
            
            if (!contents) {
                
                NSLog(@"%@\n",[error localizedDescription]);
                exit(1);
                
            } else {
                
                NSMutableString * output = [NSMutableString string];
                
                NSString * CNSTNT = @"constant value=0x";
                NSString * FIXNUM = @"fixnum value=0x"    ;
                NSString * DESCRP = @"Descriptor type=";
                NSString * HEXTXT = @"type=special value=nil>, <Value type=string value=";
                NSString * EVNTID = @"event_identifier"     ;
                NSString * POMGSD = @"PositionalMessageSend";
                NSString * ENDTLL = @"EndTell";
                NSString * ENERHN = @"EndErrorHandler";
                NSString * ERRHND = @"ErrorHandler";
                NSString * PUSLIT = @"PushLiteral";
                NSString * PUSGLB = @"PushGlobal";
                
                NSArray * lines = [contents componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet];
                
                for (NSString * thisLine in lines) {
                                    
                    if ([thisLine containsString:CNSTNT]) {
                        
                        if ([thisLine containsString:PUSLIT] || [thisLine containsString:PUSGLB]) {
                            // extract the constant hex value, convert to AEVT and look up AEVT code;
                            NSArray * components = [thisLine componentsSeparatedByString:@"="];
                            
                            if (components.count > 0) {
                                
                                NSString * last = components.lastObject;
                                
                                if (last.length > 7) {
                                    
                                    NSString * hex = [last substringWithRange:NSMakeRange(2, last.length - 5)];
                                    NSString * aevtStr = hexfunc(hex);
                                    NSString * aevt = human_readable_code(aevtStr);
                                    
                                    if (aevt.length < 1) {
                                        
                                        if (aevtStr.length == 8) {
                                            aevt = aevt_divide(aevtStr);
                                            
                                            if (aevt.length < 1) {
                                                aevt = [NSString stringWithFormat:@"String Constant:  '%@'",aevtStr];
                                            }
                                        } else {
                                            aevt = [NSString stringWithFormat:@"String Constant:  '%@'",aevtStr];
                                        }
                                    }
                                    [output appendString:[NSString stringWithFormat:@"\n%@\n  ;  %@\n", thisLine, aevt]];
                                } else {
                                    //return unchanged if error;
                                    [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                                }
                            } else {
                                //return unchanged if error;
                                [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                            }
                        } else {
                            //return unchanged if error;
                            [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                        }
                    } else if ([thisLine containsString:FIXNUM]) {
                        // append line containing hardcoded 0x number with decimal equivalent;
                        NSString * intnumStr;
                        NSRange endLoc = [thisLine rangeOfString:@">" options:NSBackwardsSearch];
                        
                        if (endLoc.location != NSNotFound) {
                            NSRange startLoc = [thisLine rangeOfString:@"=" options: NSBackwardsSearch];
                            
                            if (startLoc.location != NSNotFound) {
                                
                                intnumStr = [thisLine substringWithRange:NSMakeRange(startLoc.location + startLoc.length + 2, endLoc.location - endLoc.length - (startLoc.location + 2))];
                                
                                [output appendString:[NSString stringWithFormat:@"%@  ;  Decimal value = %lu\n", thisLine, strtol(intnumStr.UTF8String, NULL, 16)]];
                            } else {
                                //return unchanged if error;
                                [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                            }
                        } else {
                            //return unchanged if error;
                            [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                        }
                    } else if ([thisLine containsString:DESCRP]) {
                        // extract name of targeted app;
                        if ([thisLine containsString:@".app\\x"]) {
                            
                            NSRange preRange = [thisLine rangeOfString:@"<Descriptor"];
                            NSString * prefixStr = [thisLine substringToIndex:preRange.location];
                            
                            if (preRange.location != NSNotFound) {
                                
                                NSRange appNameStart = [thisLine rangeOfString:@"/"];
                                NSRange appNameEnd = [thisLine rangeOfString:@".app\\x" options:NSBackwardsSearch];
                                
                                if (appNameStart.location != NSNotFound && appNameEnd.location != NSNotFound) {
                                    
                                    NSString * appName = [thisLine substringWithRange:NSMakeRange(appNameStart.location, (appNameEnd.location - appNameStart.location))];
                                    
                                    [output appendString:[NSString stringWithFormat:@"\n%@ %@\n", prefixStr, appName]];
                                    
                                    // Nice-to-have; add path to sdef of targeted app if it exists
                                    // and isn't already included;
                                    NSString * sdef = locateAppSDEF(appName);
                                    
                                    if (sdef.length > 1) {
                                        [output appendString:[NSString stringWithFormat:@"\n  ;  Also see: '%@' for further AEVT interpretations.\n", sdef]];
                                    }
                                } else {
                                    //return unchanged if error;
                                    [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                                }
                            } else {
                                //return unchanged if error;
                                [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                            }
                        } else {
                            //return unchanged if error;
                            [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                        }
                    } else if ([thisLine containsString:HEXTXT]) {
                        NSRange prefixRange = [thisLine rangeOfString:@"[<Value"];
                        
                        if (prefixRange.location != NSNotFound) {
                            
                            NSString * prefix = [thisLine substringToIndex:prefixRange.location];
                            NSString * valPattern = @"<Value type=string value=b";
                            NSRange startRange = [thisLine rangeOfString:valPattern];
                            
                            if (startRange.location != NSNotFound) {
                                
                                NSString * stringVal = [thisLine substringFromIndex:startRange.location + startRange.length];
                                NSRange endLoc = [stringVal rangeOfString:@">" options:NSBackwardsSearch];
                                
                                if (endLoc.location != NSNotFound) {
                                    funcParam = [stringVal substringToIndex:endLoc.location];
                                    
                                    if (funcParam.length < 3) {
                                        NSRange startRange2 = [thisLine rangeOfString:valPattern];
                                        
                                        if (startRange2.location != NSNotFound) {
                                            
                                            NSString * stringVal2 = [thisLine substringFromIndex:startRange2.location + startRange2.length];
                                            NSRange  endRange2 = [stringVal2 rangeOfString:@">" options:NSBackwardsSearch];
                                            NSString * retVal2 = [stringVal2 substringToIndex:endRange2.location];
                                            [output appendString:[NSString stringWithFormat:@"\n%@ ;  String: %@\n", prefix, retVal2]];
                                            
                                        } else {
                                            [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                                        }
                                    } else {
                                        
                                        NSString * x = [funcParam stringByReplacingOccurrencesOfString:@"\\x" withString:@"\n"];
                                        NSArray * xs = [x componentsSeparatedByString:@"\n"];
                                        NSMutableString * cc = [NSMutableString string];
                                        
                                        for (NSString * i in xs) {
                                            
                                            NSString * ii = [i stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"'"]];
                                            
                                            if (ii.length == 2 && ![ii containsString:@"00"]) {
                                                [cc appendString:ii];
                                            }
                                        }
                                        
                                        if (cc.length > 0) {
                                            funcParam = cc;
                                        }
                                        
                                        [output appendString:[NSString stringWithFormat:@"\n%@ ;  String: %@\n", prefix, funcParam]];
                                    }
                                } else {
                                    //return orignal line;
                                    [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                                }
                            } else {
                                //return orignal line;
                                [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                            }
                        }
                    } else if ([thisLine containsString:EVNTID]) {
                        
                        if ([thisLine containsString:@"aevt"] && [thisLine containsString:@"oapp"]) {
                            NSRange oaPrefix = [thisLine rangeOfString:@": <"];
                            
                            if (oaPrefix.location != NSNotFound) {
                                
                                NSString * oaPrefixStr = [thisLine substringToIndex:oaPrefix.location +2];
                                [output appendString:[NSString stringWithFormat:@"\n%@ 'Open Application' \n", oaPrefixStr]];
                                
                            } else {
                                //return orignal line;
                                [output appendString:[NSString stringWithFormat:@"\n%@\n", thisLine]];
                            }
                        } else {
                            // 8-char event identifiers;
                            NSRange eid = [thisLine rangeOfString:@"=event_identifier value="];
                            
                            if (eid.location != NSNotFound) {
                                
                                NSString * val = [thisLine substringFromIndex:eid.location + eid.length];
                                NSString * vals = aevt_group(val);
                                
                                [output appendString:[NSString stringWithFormat:@"\n%@\n  ;  %@\n", thisLine, vals]];
                            }
                        }
                    } else if ([thisLine containsString:POMGSD]) {
                        // calls to other AS Handlers in the script;
                        if ([thisLine hasSuffix:@"'d' "]) {
                            /*
                             This is a custom handler for this specific malware
                             df550039acad9e637c7c3ec2a629abf8b3f35faca18e58d447f490cf23f114e8
                             */
                            NSString * decodedStr = decode(funcParam, 100);
                            
                            if (decodedStr.length > 0) {
                                
                                NSString * o = [output stringByReplacingOccurrencesOfString:[NSString stringWithFormat:@"#  ;  String: %@", funcParam] withString:[NSString stringWithFormat:@"  ;  String: %@\n\t  Decoded String: '%@'", funcParam, decodedStr]];
                                
                                [output setString:o];
                                [output appendFormat:@"\n%@\n\t;  Function Call\n", thisLine];
                            
                            } else {
                                [output appendFormat:@"\n%@\n\t;  Function Call\n", thisLine];
                            }
                        } else {
                            [output appendFormat:@"\n%@\n\t;  Function Call\n", thisLine];
                        }
                    } else if ([thisLine containsString:ENDTLL]) {
                        //TODO: ENDTLL
                        [output appendFormat:@"\n%@\n", thisLine];
                    } else if ([thisLine containsString:ENERHN]) {
                        //TODO: ENERHN
                        [output appendFormat:@"\n%@\n", thisLine];
                    } else if ([thisLine containsString:ERRHND]) {
                        //TODO: ERRHND
                        [output appendFormat:@"\n%@\n", thisLine];
                    } else {
                        [output appendFormat:@"\n%@\n", thisLine];
                    }
                }
                
                // Some final tidying up;
                NSMutableString * finalisedStr = [NSMutableString string];
                NSArray * finalArray = [output componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet];
                
                NSString * findPattern1 = @"String: '\\x00";
                NSString * findPattern2 = @"String: \"\\x00";
                NSString * findPattern3 = @"\\\\x";
                NSString * findPattern4 = @"'\\x'";
                NSString * findPattern5 = @"'\\x00'";
                NSString * findPattern6 = @"\\x";
                
                NSString * remove = @"";
                NSString * space = @" ";
                NSString * replPattern_1_2 = @"\\x00";
                
                for (NSString * f in finalArray) {
                    
                    if ([f containsString:findPattern1] || [f containsString:findPattern2]) {
                        
                        NSString * replacementStr = [f stringByReplacingOccurrencesOfString:replPattern_1_2 withString:remove];
                        
                        if ([replacementStr containsString:findPattern3]) {
                            replacementStr = [replacementStr stringByReplacingOccurrencesOfString:findPattern3 withString:findPattern6];
                        }
                        
                        if (![replacementStr containsString:findPattern4] && ![replacementStr containsString:findPattern5]) {
                            replacementStr = [replacementStr stringByReplacingOccurrencesOfString:findPattern6 withString:space];
                        }
                        
                        [finalisedStr appendFormat:@"%@\n", replacementStr];
                        
                    } else {
                        [finalisedStr appendFormat:@"%@\n", f];
                    }
                }
                
                NSError * wrErr;
                NSString * sourceFile = [[path lastPathComponent] stringByDeletingPathExtension];
                
                /*
                 Location to write out to;
                 Bear in mind macOS restriction on code writing to ~/Desktop, so change as preferred;
                 */
                NSString * user = NSUserName();
                NSString * homeDir = NSHomeDirectoryForUser(user);
                NSString * outFile = [NSString stringWithFormat:@"%@/Desktop/%@.out", homeDir, sourceFile];
                NSURL *w = [NSURL fileURLWithPath:outFile];
                
                if (![finalisedStr writeToURL:w atomically:true encoding:NSUTF8StringEncoding error:&wrErr]) {
                
                    NSLog(@"%@", wrErr);
                }
            }
        } else {
            /*
             Note that we don't do any checking on the file type;
             The script takes as input a text file output by AppleScript-Disassembler.
             */
            NSLog(@"Usage: aevt_decompile <file>\n");
            exit(1);
        }
    }
    return 0;
}


NSArray * ae_frameworks() {
    
    NSError * err = nil;
    NSString * sdkPath = @"/Library/Developer/CommandLineTools/SDKs/";
    
    NSArray * headerPaths = @[
        @"/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/Headers/AERegistry.h",
        @"/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/Headers/AEDataModel.h",
        @"/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/Headers/AppleEvents.h"
    ];
    
    NSFileManager * fm = [NSFileManager defaultManager];
    NSArray * sdkDir = [fm contentsOfDirectoryAtPath:sdkPath error:&err];
    
    if (sdkDir == nil) {
        NSLog(@"%@\n", err.localizedDescription);
    } else {
        
        NSPredicate * filter = [NSPredicate predicateWithFormat:@"self ENDSWITH '.sdk'"];
        NSArray * sdks = [sdkDir filteredArrayUsingPredicate:filter];
        
        if (sdks.count > 0) {
            
            NSString *sdkBase = [sdkPath stringByAppendingPathComponent:sdks[0]];
            NSMutableArray * headers = [NSMutableArray array];
            for (NSString *header in headerPaths) {
                [headers addObject:[sdkBase stringByAppendingPathComponent:header]];
            }
            
            return  headers;
        }
    }
    return @[];
}


NSString * aevt_divide(NSString * hexStr) {
    
    if (hexStr.length == 8) {
        
        NSString * first = [hexStr substringToIndex:4];
        NSString * second = [hexStr substringFromIndex:4];
        NSString * firstReadable = human_readable_code(first);
        NSString * secondReadable = human_readable_code(second);
        
        NSString * concat = [NSString stringWithFormat:@"String Constant: '%@':\n%@\n%@", hexStr, firstReadable, secondReadable];
        
        return concat;
        
    }
    return hexStr;
}

NSString * aevt_group(NSString * codeStr) {
    
    NSArray * codeList = [codeStr componentsSeparatedByString:@"'"];
    NSMutableString * combined = [NSMutableString string];
    
    for (NSString * ch in codeList) {
        
        if (ch.length == 4) {
            const char * c = ch.UTF8String;
            
            if (isalpha(* c)) {
                
                if (combined.length == 0) {
                    [combined appendString:ch];
            
                } else if (combined.length == 8) {
                    combined = [NSMutableString string];
                    
                } else {
                    
                    [combined appendString:ch];
                    return human_readable_code(combined);
                }
            }
        }
    }
    return codeStr;
}

NSString * decode(NSString * hex, int d) {
    
    NSString * hStr = [hex stringByTrimmingCharactersInSet:[NSCharacterSet punctuationCharacterSet]];
    
    if (hStr.length % 2 == 0) {
        
        NSMutableString * decoded = [NSMutableString string];
        
        for (int i = 0; i < hStr.length; i += 2) {
            
            NSString * intnumStr = [hStr substringWithRange:NSMakeRange(i, 2)];
            long hexl = strtol(intnumStr.UTF8String, NULL, 16);
            int asciil = (int)hexl - 100;
            NSString * c = [NSString stringWithFormat:@"%c", asciil];
            [decoded appendString:c];
        }
        
        if (decoded.length > 0) {
            return decoded;
        }
    }
    return hex;
}

NSString * hexfunc(NSString * hex) {
    
    if (hex.length % 2 == 0) {
        
        NSMutableString * aevtStr = [NSMutableString string];
        
        for (int i = 0; i < hex.length; i += 2) {
            
            unsigned decimal = 0;
            NSString * hexbyte = [hex substringWithRange:NSMakeRange(i, 2)];
            NSScanner * scanner = [NSScanner scannerWithString:hexbyte];
            
            if (scanner != nil) {
                
                [scanner scanHexInt:&decimal];
                [aevtStr appendString:[NSString stringWithFormat:@"%c", decimal]];
            }
        }
        
        if (aevtStr.length > 0) {
            return aevtStr;
        }
    }
    return hex;
}

NSString * human_readable_code(NSString * searchStr) {
    
    NSArray * sdefs = @[
        @"/System/Library/CoreServices/System Events.app/Contents/Resources/SystemEvents.sdef",
        @"/System/Library/ScriptingAdditions/StandardAdditions.osax/Contents/Resources/StandardAdditions.sdef",
        @"/System/Applications/Utilities/Terminal.app/Contents/Resources/Terminal.sdef",
        @"/System/Library/Frameworks/AppleScriptKit.framework/Versions/A/Resources/AppleScriptKit.sdef"
    ];
    
    NSArray * headers = ae_frameworks();
    NSMutableArray * sources = [headers mutableCopy];
    
    if (sources.count == 0) {
        NSLog(@"aevt_decompile: Install Xcode Command Line Tools to fully decompile all AEVT codes.\n");
    }
    
    [sources addObjectsFromArray:sdefs];
    
    NSMutableString * resultStr = [NSMutableString string];

    for (NSString * aevt in sources) {
        
        NSError  * err;
        NSString * aevtName = [aevt lastPathComponent];
        NSURL * aevtURL = [NSURL fileURLWithPath:aevt];
        NSString * fileContents = [NSString stringWithContentsOfURL:aevtURL encoding:NSUTF8StringEncoding error:&err];
        
        if (fileContents != nil) {

            NSArray * fileLines = [fileContents componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet];
            
            NSString * formatTypeA = [NSString stringWithFormat:@"\"%@\"", searchStr];
            NSString * formatTypeB = [NSString stringWithFormat:@"\'%@\'", searchStr];
            
            for (NSString * ln in fileLines) {
                
                if ([ln containsString:formatTypeA] || [ln containsString:formatTypeB])   {
                    
                    if (![resultStr containsString:ln]) {
                        [resultStr appendString:[NSString stringWithFormat:@"\t%@ --> in %@\n", ln, aevtName]];
                    }
                }
            }
        } else {
            NSLog(@"Could not read file: '%@'", aevt);
        }
    }
    return resultStr;
}

// TODO: we can improve this to actually fetch the codes rather than just suggest the path;
NSString * locateAppSDEF(NSString *str) {
    
    NSString * appStr = [str stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
       
    // These two are already hardcoded in human_readable_code function;
    if (![appStr containsString:@"/System Events"] && ![appStr containsString:@"/Terminal"]) {
        
        NSMutableString * app = [NSMutableString string];
        // Could be fragile; likely needs adjusting in light of more examples;
        if ([appStr hasPrefix:@"/Utilities"]) {
            [app appendString:[NSString stringWithFormat:@"/Applications%@", appStr]];
            
        } else if (![appStr hasPrefix:@"/"]) {
            [app appendString:[NSString stringWithFormat:@"/%@", appStr]];
            
        } else {
            [app appendString:appStr];
        }
        
        // [appStr lastPathComponent];
         if (![app hasSuffix:@".app"]) {
            [app appendString:@".app"];
        }
        
        // TODO: A little fragile; it assumes the SDEF is named after the application, which is not always true;
        // Better to enumerate and return any sdefs in the Resources folder
        NSString * sdefFile = [NSString stringWithFormat:@"%@/Contents/Resources/%@.sdef", app, [appStr lastPathComponent]];
        
        // Should probably change to NSURL at some point...
        if ([[NSFileManager defaultManager] fileExistsAtPath:sdefFile]) {
            return sdefFile;
        }
    }
    return @"";
}
