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
    [NSUserDefaults.standardUserDefaults setObject:bookmark forKey:kJITStrictFailureDirectoryBookmark];
    return YES;
}

void ish_write_jit_strict_failure(const char *reason, uint64_t pc, uint32_t insn) {
    NSLog(@"iSH JIT strict diagnostic callback invoked");
    NSString *report = [NSString stringWithFormat:@"JIT strict mode: %s\nguest pc: 0x%llx\ninstruction: 0x%08x\n",
                                                  reason, (unsigned long long) pc, insn];
    NSData *data = [report dataUsingEncoding:NSUTF8StringEncoding];
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSData *bookmark = [defaults dataForKey:kJITStrictFailureDirectoryBookmark];
    NSURL *directory = nil;
    NSError *error = nil;
    BOOL hasScopedAccess = NO;
    if (bookmark != nil) {
        BOOL stale = NO;
        directory = [NSURL URLByResolvingBookmarkData:bookmark
                                              options:0
                                        relativeToURL:nil
                                  bookmarkDataIsStale:&stale
                                                error:&error];
        if (directory != nil && !stale)
            hasScopedAccess = [directory startAccessingSecurityScopedResource];
        if (directory == nil || stale || !hasScopedAccess) {
            NSLog(@"iSH JIT strict diagnostic: selected folder unavailable (stale=%d, error=%@)",
                  stale, error);
            directory = nil;
        }
    }

    if (directory == nil)
        directory = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory
                                                         inDomains:NSUserDomainMask].firstObject;
    if (directory == nil) {
        NSLog(@"iSH JIT strict diagnostic: no writable destination is available");
        return;
    }

    NSURL *fileURL = [directory URLByAppendingPathComponent:@"ISH-JIT-STRICT-FAILURE.txt"];
    error = nil;
    BOOL saved = [data writeToURL:fileURL options:NSDataWritingAtomic error:&error];
    if (saved) {
        NSLog(@"iSH JIT strict diagnostic saved to %@", fileURL.path);
    } else if (hasScopedAccess) {
        NSLog(@"iSH JIT strict diagnostic: could not write selected folder %@: %@; trying Documents",
              fileURL.path, error);
        [directory stopAccessingSecurityScopedResource];
        hasScopedAccess = NO;
        NSURL *documents = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory
                                                                  inDomains:NSUserDomainMask].firstObject;
        if (documents == nil) {
            NSLog(@"iSH JIT strict diagnostic: fallback Documents folder is unavailable");
        } else {
            fileURL = [documents URLByAppendingPathComponent:@"ISH-JIT-STRICT-FAILURE.txt"];
            error = nil;
            saved = [data writeToURL:fileURL options:NSDataWritingAtomic error:&error];
            if (saved)
                NSLog(@"iSH JIT strict diagnostic saved to fallback %@", fileURL.path);
            else
                NSLog(@"iSH JIT strict diagnostic: fallback write failed for %@: %@", fileURL.path, error);
        }
    } else {
        NSLog(@"iSH JIT strict diagnostic: could not write %@: %@", fileURL.path, error);
    }
    if (hasScopedAccess)
        [directory stopAccessingSecurityScopedResource];
}
