// CVE-2026-86950 harness: ImageIO PDF thumbnail (WhatsApp/iMessage path).
// No CGContext created here, no font-smoothing calls — ImageIO's own
// internal render context is what reaches the vulnerable code.
//
// Gate 0 (PLAN/GLYPHGRIFT_CHAIN_FIX_PLAN.md Phase 0): run this against the
// research PDF (control) and the bundled PDFs. A crashing build proves the
// payload reaches aa_cache_render; "survived" means the bytes are wrong.
#include <ImageIO/ImageIO.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "trigger.pdf";
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)path, strlen(path), false);
    CGImageSourceRef src = CGImageSourceCreateWithURL(url, NULL);
    CFRelease(url);
    if (!src) { fprintf(stderr, "CGImageSourceCreateWithURL failed\n"); return 2; }

    int sz = 256;
    CFStringRef k[] = { kCGImageSourceCreateThumbnailFromImageAlways,
                        kCGImageSourceThumbnailMaxPixelSize };
    CFTypeRef   v[] = { kCFBooleanTrue,
                        CFNumberCreate(NULL, kCFNumberIntType, &sz) };
    CFDictionaryRef opts = CFDictionaryCreate(NULL, (const void **)k,
        (const void **)v, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    fprintf(stderr, "creating thumbnail: %s ...\n", path);
    CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
    fprintf(stderr, "survived (patched build): img=%p\n", (void *)img);
    if (img) CFRelease(img);
    if (opts) CFRelease(opts);
    CFRelease(src);
    return 0;
}
