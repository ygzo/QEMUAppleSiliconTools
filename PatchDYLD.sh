#!/usr/bin/env bash

set -e

if [ ! -f dyld_shared_cache_arm64e.orig ]; then
    echo "Original shared cache is not in place."
    exit
fi

echo "Restoring original DYLD..."
cp dyld_shared_cache_arm64e.orig dyld_shared_cache_arm64e

echo "Applying CoreImage patches..."
# Force `wrapGLIsUsable` to return false
printf '\x00\x00\x80\xD2' | dd bs=1 count=4 seek=0x1E8F704 conv=notrunc of=dyld_shared_cache_arm64e
printf '\xC0\x03\x5F\xD6' | dd bs=1 count=4 seek=0x1E8F708 conv=notrunc of=dyld_shared_cache_arm64e

echo "Applying QuartzCore patches..."
# Fix `CA::OGL::AsynchronousDispatcher::renderer` to use software context
printf '\x1F\x20\x03\xD5' | dd bs=1 count=4 seek=0x81435F0 conv=notrunc of=dyld_shared_cache_arm64e
printf '\x1F\x20\x03\xD5' | dd bs=1 count=4 seek=0x81435F4 conv=notrunc of=dyld_shared_cache_arm64e
printf '\x1F\x20\x03\xD5' | dd bs=1 count=4 seek=0x81435F8 conv=notrunc of=dyld_shared_cache_arm64e
printf '\xDD\x18\x02\x94' | dd bs=1 count=4 seek=0x814360C conv=notrunc of=dyld_shared_cache_arm64e
printf '\x1F\x20\x03\xD5' | dd bs=1 count=4 seek=0x8143660 conv=notrunc of=dyld_shared_cache_arm64e
printf '\x1F\x20\x03\xD5' | dd bs=1 count=4 seek=0x8143664 conv=notrunc of=dyld_shared_cache_arm64e

echo "Applying SpringBoardFoundation.framework patches..."
# Force `shouldUseXPCForRendering` to return true
printf '\x20\x00\x80\xD2' | dd bs=1 count=4 seek=0x15E94F18 conv=notrunc of=dyld_shared_cache_arm64e
printf '\xC0\x03\x5F\xD6' | dd bs=1 count=4 seek=0x15E94F1C conv=notrunc of=dyld_shared_cache_arm64e

echo "Moving patched DYLD..."
mv dyld_shared_cache_arm64e /Volumes/System/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e
