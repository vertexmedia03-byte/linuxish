//
//  AppGroup.m
//  iSH
//
//  Created by Theodore Dubois on 2/28/20.
//

#import "AppGroup.h"
#import <Foundation/Foundation.h>
#import <mach-o/ldsyms.h>
#import <mach-o/loader.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>

#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_EMBEDDED_ENTITLEMENTS 0xfade7171

struct cs_blob_index {
    uint32_t type;
    uint32_t offset;
};

struct cs_superblob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    struct cs_blob_index index[];
};

struct cs_entitlements {
    uint32_t magic;
    uint32_t length;
    char entitlements[];
};

static NSDictionary *AppEntitlements(void) {
    static NSDictionary *entitlements;
    if (entitlements != nil)
        return entitlements;
    
    // Inspired by codesign.c in Darwin sources for Security.framework
    
    const struct mach_header_64 *header = &_mh_execute_header;
    
    // Simulator executables have fake entitlements in the code signature. The real entitlements can be found in an __entitlements section.
    size_t entitlements_size;
    char *entitlements_data = (char *) getsectiondata(header, "__TEXT", "__entitlements", &entitlements_size);
    if (entitlements_data != NULL) {
        NSData *data = [NSData dataWithBytesNoCopy:entitlements_data
                                            length:entitlements_size
                                      freeWhenDone:NO];
        return entitlements = [NSPropertyListSerialization propertyListWithData:data
                                                                        options:NSPropertyListImmutable
                                                                         format:nil
                                                                          error:nil];
    }
    
    // Find the LC_CODE_SIGNATURE
    struct load_command *lc = (void *) (header + 1);
    struct linkedit_data_command *cs_lc = NULL;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_CODE_SIGNATURE) {
            cs_lc = (void *) lc;
            break;
        }
        lc = (void *) ((char *) lc + lc->cmdsize);
    }
    if (cs_lc == NULL)
        return nil;

    // Read the code signature off disk, as it's apparently not loaded into memory
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingFromURL:NSBundle.mainBundle.executableURL error:nil];
    if (fileHandle == nil)
        return nil;
    [fileHandle seekToFileOffset:cs_lc->dataoff];
    NSData *csData = [fileHandle readDataOfLength:cs_lc->datasize];
    [fileHandle closeFile];
    const struct cs_superblob *cs = csData.bytes;
    if (ntohl(cs->magic) != CSMAGIC_EMBEDDED_SIGNATURE)
        return nil;
    
    // Find the entitlements in the code signature
    NSData *entitlementsData = nil;
    for (uint32_t i = 0; i < ntohl(cs->count); i++) {
        struct cs_entitlements *ents = (void *) ((char *) cs + ntohl(cs->index[i].offset));
        if (ntohl(ents->magic) == CSMAGIC_EMBEDDED_ENTITLEMENTS) {
            entitlementsData = [NSData dataWithBytes:ents->entitlements
                                              length:ntohl(ents->length) - offsetof(struct cs_entitlements, entitlements)];
        }
    }
    if (entitlementsData == nil)
        return nil;
    
    return entitlements = [NSPropertyListSerialization propertyListWithData:entitlementsData
                                                                    options:NSPropertyListImmutable
                                                                     format:nil
                                                                      error:nil];
}

NSArray<NSString *> *CurrentAppGroups(void) {
    return AppEntitlements()[@"com.apple.security.application-groups"];
}

NSURL *ContainerURL(void) {
    NSString *appGroup = CurrentAppGroups()[0];
    return [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:appGroup];
}

static NSString *const kJITStrictFailureDirectoryBookmark = @"JIT Strict Failure Directory Bookmark";

BOOL SetJITStrictFailureDirectory(NSURL *url, NSError **error) {
    NSData *bookmark = [url bookmarkDataWithOptions:0
                     includingResourceValuesForKeys:nil
                                      relativeToURL:nil
                                              error:error];
    if (bookmark == nil)
        return NO;
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    [defaults setObject:bookmark forKey:kJITStrictFailureDirectoryBookmark];
    if ([defaults synchronize])
        return YES;
    if (error != NULL)
        *error = [NSError errorWithDomain:NSCocoaErrorDomain
                                     code:NSFileWriteUnknownError
                                 userInfo:@{NSLocalizedDescriptionKey: @"Could not persist the selected report folder."}];
    return NO;
}

static NSURL *JITDiagnosticDirectory(BOOL *hasScopedAccess) {
    *hasScopedAccess = NO;
    NSData *bookmark = [NSUserDefaults.standardUserDefaults dataForKey:kJITStrictFailureDirectoryBookmark];
    if (bookmark != nil) {
        BOOL stale = NO;
        NSError *error = nil;
        NSURL *directory = [NSURL URLByResolvingBookmarkData:bookmark
                                                     options:0
                                               relativeToURL:nil
                                         bookmarkDataIsStale:&stale
                                                       error:&error];
        if (directory != nil && !stale)
            *hasScopedAccess = [directory startAccessingSecurityScopedResource];
        if (directory != nil && !stale && *hasScopedAccess)
            return directory;
        NSLog(@"iSH JIT diagnostic: selected folder unavailable (stale=%d, error=%@)",
              stale, error);
    }

    return [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory
                                                inDomains:NSUserDomainMask].firstObject;
}

static BOOL WriteJITDiagnosticData(NSData *data, NSURL *url, NSError **error) {
    NSFileManager *fileManager = NSFileManager.defaultManager;
    if (![fileManager fileExistsAtPath:url.path] &&
        ![[NSData data] writeToURL:url options:NSDataWritingAtomic error:error])
        return NO;

    NSFileHandle *file = [NSFileHandle fileHandleForWritingToURL:url error:error];
    if (file == nil)
        return NO;
    BOOL success = [file seekToEndReturningOffset:NULL error:error] &&
                   [file writeData:data error:error] &&
                   [file synchronizeAndReturnError:error];
    NSError *closeError = nil;
    if (![file closeAndReturnError:&closeError]) {
        if (success && error != NULL)
            *error = closeError;
        success = NO;
    }
    return success;
}

void ish_write_jit_trace(const char *event, uint64_t pc, uint64_t detail, bool reset) {
    @autoreleasepool {
        @synchronized (NSFileManager.defaultManager) {
            BOOL hasScopedAccess = NO;
            NSURL *directory = JITDiagnosticDirectory(&hasScopedAccess);
            if (directory == nil) {
                NSLog(@"iSH JIT trace: no writable destination is available");
                return;
            }

            NSString *line = [NSString stringWithFormat:@"%.3f %s pc=0x%llx detail=0x%llx\n",
                                                        NSDate.date.timeIntervalSince1970,
                                                        event,
                                                        (unsigned long long) pc,
                                                        (unsigned long long) detail];
            NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
            NSURL *url = [directory URLByAppendingPathComponent:@"ISH-JIT-TRACE.log"];
            NSError *error = nil;
            BOOL success = reset
                ? [data writeToURL:url options:NSDataWritingAtomic error:&error]
                : WriteJITDiagnosticData(data, url, &error);
            if (success) {
                if (reset)
                    NSLog(@"iSH JIT trace started at %@", url.path);
            } else {
                NSLog(@"iSH JIT trace write failed for %@: %@", url.path, error);
                if (hasScopedAccess)
                    [directory stopAccessingSecurityScopedResource];
                NSURL *documents = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory
                                                                          inDomains:NSUserDomainMask].firstObject;
                if (documents == nil || [documents isEqual:directory]) {
                    NSLog(@"iSH JIT trace: fallback Documents destination is unavailable");
                    return;
                }
                url = [documents URLByAppendingPathComponent:@"ISH-JIT-TRACE.log"];
                error = nil;
                success = reset
                    ? [data writeToURL:url options:NSDataWritingAtomic error:&error]
                    : WriteJITDiagnosticData(data, url, &error);
                if (success && reset)
                    NSLog(@"iSH JIT trace started at fallback %@", url.path);
                else if (!success)
                    NSLog(@"iSH JIT trace fallback write failed for %@: %@", url.path, error);
                return;
            }
            if (hasScopedAccess)
                [directory stopAccessingSecurityScopedResource];
        }
    }
}

void ish_write_jit_strict_failure(const char *reason, uint64_t pc, uint32_t insn) {
    @autoreleasepool {
        NSString *report = [NSString stringWithFormat:@"JIT strict mode: %s\nguest pc: 0x%llx\ninstruction: 0x%08x\n",
                                                      reason, (unsigned long long) pc, insn];
        NSData *data = [report dataUsingEncoding:NSUTF8StringEncoding];
        BOOL hasScopedAccess = NO;
        NSURL *directory = JITDiagnosticDirectory(&hasScopedAccess);
        if (directory == nil) {
            NSLog(@"iSH JIT strict diagnostic: no writable destination is available");
            return;
        }
        NSURL *fileURL = [directory URLByAppendingPathComponent:@"ISH-JIT-STRICT-FAILURE.txt"];
        NSError *error = nil;
        BOOL saved = [data writeToURL:fileURL options:NSDataWritingAtomic error:&error];
        if (!saved) {
            NSLog(@"iSH JIT strict diagnostic: could not write %@: %@", fileURL.path, error);
            if (hasScopedAccess)
                [directory stopAccessingSecurityScopedResource];
            return;
        }
        NSLog(@"iSH JIT strict diagnostic saved to %@", fileURL.path);
        if (hasScopedAccess)
            [directory stopAccessingSecurityScopedResource];
    }
}
