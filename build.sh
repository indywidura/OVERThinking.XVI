#!/bin/bash

# Defined path
MainPath="$(pwd)"
Proton="$(pwd)/../Proton"
DTC="$(pwd)/../DragonTC"
GCC64="$(pwd)/../GCC64"
GCC="$(pwd)/../GCC"
gcc64="$(pwd)/../gcc64"
gcc="$(pwd)/../gcc"
Any="$(pwd)/../AnyKernel3"

# Upload to telegram
UT=0
if [ $UT = 1 ]; then
    BOT_TOKEN="1743572055:AAFrucA6-YfaxQUeCwCFrAPw6LEMQUITSxQ"
    CHAT_ID="-1001584611536"
fi

msg() {
    curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d chat_id="$CHAT_ID" \
    -d "disable_web_page_preview=true" \
    -d "parse_mode=html" \
    -d text="$Text"
}

Upload() {
    curl -F chat_id="$CHAT_ID" \
    -F document=@"$FILE" \
    -F parse_mode=markdown https://api.telegram.org/bot$BOT_TOKEN/sendDocument \
    -F caption="$Caption"
}

# Make flashable zip
MakeZip() {
    if [ ! -d $Any ]; then
        git clone https://github.com/TeraaBytee/AnyKernel3 -b master $Any
        cd $Any
    else
        cd $Any
        git reset --hard
        git checkout master
        git fetch origin master
        git reset --hard origin/master
    fi
    cp -af $MainPath/out/arch/arm64/boot/Image.gz-dtb $Any
    sed -i "s/kernel.string=.*/kernel.string=$KERNEL_NAME-$HeadCommit test by $KBUILD_BUILD_USER/g" anykernel.sh
    zip -r9 $MainPath/"[$Compiler][R-OSS]-$ZIP_KERNEL_VERSION-$KERNEL_NAME-$TIME.zip" * -x .git README.md *placeholder
    cd $MainPath
}

# Clone compiler
Clone_GCC() {
    if [ $UT = 1 ]; then
        Text="Clone compiler"
        msg
    fi
    if [ ! -d $GCC64 ]; then
        git clone --depth=1 https://github.com/mvaisakh/gcc-arm64 -b gcc-master $GCC64
    else
        cd $GCC64
        git fetch origin gcc-master
        git checkout FETCH_HEAD
        git branch -D gcc-master
        git branch gcc-master && git checkout gcc-master
        cd $MainPath
    fi
    GCC64_Version="$($GCC64/bin/*gcc --version | grep gcc)"

    if [ ! -d $GCC ]; then
        git clone --depth=1 https://github.com/mvaisakh/gcc-arm -b gcc-master $GCC
    else
        cd $GCC
        git fetch origin gcc-master
        git checkout FETCH_HEAD
        git branch -D gcc-master
        git branch gcc-master && git checkout gcc-master
        cd $MainPath
    fi
    GCC_Version="$($GCC/bin/*gcc --version | grep gcc)"
}

Clone_Proton() {
    if [ $UT = 1 ]; then
        Text="Clone compiler"
        msg
    fi
    if [ ! -d $Proton ]; then
        git clone --depth=1 https://github.com/kdrag0n/proton-clang -b master $Proton
    else
        cd $Proton
        git fetch origin master
        git checkout FETCH_HEAD
        git branch -D master
        git branch master && git checkout master
        cd $MainPath
    fi
    Proton_Version="$($Proton/bin/clang --version | grep clang)"
}

Clone_DTC() {
    if [ $UT = 1 ]; then
        Text="Clone compiler"
        msg
    fi
    if [ ! -d $DTC ]; then
        git clone --depth=1 https://github.com/TeraaBytee/DragonTC $DTC
    else
        cd $DTC
        git fetch origin 10.0
        git checkout FETCH_HEAD
        git branch -D 10.0
        git branch 10.0 && git checkout 10.0
        cd $MainPath
    fi
    DTC_Version="$($DTC/bin/clang --version | grep clang)"

    if [ ! -d $gcc64 ]; then
        git clone --depth=1 https://github.com/TeraaBytee/aarch64-linux-android-4.9 $gcc64
    else
        cd $gcc64
        git fetch origin master
        git checkout FETCH_HEAD
        git branch -D master
        git branch master && git checkout master
        cd $MainPath
    fi
    if [ ! -d $gcc ]; then
        git clone --depth=1 https://github.com/TeraaBytee/arm-linux-androideabi-4.9 $gcc
    else
        cd $gcc
        git fetch origin master
        git checkout FETCH_HEAD
        git branch -D master
        git branch master && git checkout master
        cd $MainPath
    fi
}

# Defined config
HeadCommit="$(git log --pretty=format:'%h' -1)"
export ARCH="arm64"
export SUBARCH="arm64"
export KBUILD_BUILD_USER="Sayonara"
export KBUILD_BUILD_HOST="OVER-XVI"
Defconfig="begonia_user_defconfig"
KERNEL_NAME=$(cat "$MainPath/arch/arm64/configs/$Defconfig" | grep "CONFIG_LOCALVERSION=" | sed 's/CONFIG_LOCALVERSION="-*//g' | sed 's/"*//g' )
ZIP_KERNEL_VERSION="4.14.$(cat "$MainPath/Makefile" | grep "SUBLEVEL =" | sed 's/SUBLEVEL = *//g')$(cat "$(pwd)/Makefile" | grep "EXTRAVERSION =" | sed 's/EXTRAVERSION = *//g')"

# Start building
Build_GCC() {
    Compiler=GCC
    if [ $UT = 1 ]; then
        Text="<b>Device</b>: <code>Redmi Note 8 Pro [BEGONIA]</code>%0A<b>Branch</b>: <code>$(git branch | grep '*' | awk '{ print $2 }')</code>%0A<b>Kernel name</b>: <code>$(cat "arch/arm64/configs/begonia_user_defconfig" | grep "CONFIG_LOCALVERSION=" | sed 's/CONFIG_LOCALVERSION="-*//g' | sed 's/"*//g' )</code>%0A<b>Kernel version</b>: <code>4.14.$(cat "Makefile" | grep "SUBLEVEL =" | sed 's/SUBLEVEL = *//g')</code>%0A<b>Build user</b>: <code>$KBUILD_BUILD_USER</code>%0A<b>Build host</b>: <code>$KBUILD_BUILD_HOST</code>%0A<b>Cross compile</b>:%0A<code>$GCC64_Version</code>%0A<b>Cross compile arm32</b>:%0A<code>$GCC_Version</code>%0A<b>Changelogs</b>:%0A<code>$(git log --oneline -5 --no-decorate)</code>"
        msg
    fi
    rm -rf out
    TIME=$(date +"%m%d%H%M")
    BUILD_START=$(date +"%s")

    make  -j$(nproc --all)  O=out ARCH=arm64 SUBARCH=arm64 $Defconfig
    exec 2> >(tee -a out/error.log >&2)
    make  -j$(nproc --all)  O=out \
                            PATH="$GCC64/bin:$GCC/bin:/usr/bin:$PATH" \
                            AR=aarch64-elf-ar \
                            NM=llvm-nm \
                            LD=ld.lld \
                            OBCOPY=llvm-objcopy \
                            OBJDUMP=aarch64-elf-objdump \
                            STRIP=aarch64-elf-strip \
                            CROSS_COMPILE=aarch64-elf- \
                            CROSS_COMPILE_ARM32=arm-eabi-
}

Build_Proton() {
    Compiler=Proton
    if [ $UT = 1 ]; then
        Text="<b>Device</b>: <code>Redmi Note 8 Pro [BEGONIA]</code>%0A<b>Branch</b>: <code>$(git branch | grep '*' | awk '{ print $2 }')</code>%0A<b>Kernel name</b>: <code>$(cat "arch/arm64/configs/begonia_user_defconfig" | grep "CONFIG_LOCALVERSION=" | sed 's/CONFIG_LOCALVERSION="-*//g' | sed 's/"*//g' )</code>%0A<b>Kernel version</b>: <code>4.14.$(cat "Makefile" | grep "SUBLEVEL =" | sed 's/SUBLEVEL = *//g')</code>%0A<b>Build user</b>: <code>$KBUILD_BUILD_USER</code>%0A<b>Build host</b>: <code>$KBUILD_BUILD_HOST</code>%0A<b>Compiler</b>:%0A<code>$Proton_Version</code>%0A<b>Changelogs</b>:%0A<code>$(git log --oneline -5 --no-decorate)</code>"
        msg
    fi
    rm -rf out
    TIME=$(date +"%m%d%H%M")
    BUILD_START=$(date +"%s")

    make  -j$(nproc --all)  O=out ARCH=arm64 SUBARCH=arm64 $Defconfig
    exec 2> >(tee -a out/error.log >&2)
    make  -j$(nproc --all)  O=out \
                            PATH="$Proton/bin:/usr/bin:$PATH" \
                            CC=clang \
                            AS=llvm-as \
                            NM=llvm-nm \
                            OBJCOPY=llvm-objcopy \
                            OBJDUMP=llvm-objdump \
                            STRIP=llvm-strip \
                            LD=ld.lld \
                            CROSS_COMPILE=aarch64-linux-gnu- \
                            CROSS_COMPILE_ARM32=arm-linux-gnueabi-
}

Build_DTC() {
    Compiler=DragonTC
    if [ $UT = 1 ]; then
        Text="<b>Device</b>: <code>Redmi Note 8 Pro [BEGONIA]</code>%0A<b>Branch</b>: <code>$(git branch | grep '*' | awk '{ print $2 }')</code>%0A<b>Kernel name</b>: <code>$(cat "arch/arm64/configs/begonia_user_defconfig" | grep "CONFIG_LOCALVERSION=" | sed 's/CONFIG_LOCALVERSION="-*//g' | sed 's/"*//g' )</code>%0A<b>Kernel version</b>: <code>4.14.$(cat "Makefile" | grep "SUBLEVEL =" | sed 's/SUBLEVEL = *//g')</code>%0A<b>Build user</b>: <code>$KBUILD_BUILD_USER</code>%0A<b>Build host</b>: <code>$KBUILD_BUILD_HOST</code>%0A<b>Compiler</b>:%0A<code>$DTC_Version</code>%0A<b>Changelogs</b>:%0A<code>$(git log --oneline -5 --no-decorate)</code>"
        msg
    fi
    rm -rf out
    TIME=$(date +"%m%d%H%M")
    BUILD_START=$(date +"%s")

    make  -j$(nproc --all)  O=out ARCH=arm64 SUBARCH=arm64 $Defconfig
    exec 2> >(tee -a out/error.log >&2)
    make  -j$(nproc --all)  O=out \
                            PATH="$DTC/bin:/$gcc64/bin:/$gcc/bin:/usr/bin:$PATH" \
                            LD_LIBRARY_PATH="$DTC/lib64:$LD_LIBRABRY_PATH" \
                            CC=clang \
                            LD=ld.lld \
                            CROSS_COMPILE=aarch64-linux-android- \
                            CROSS_COMPILE_ARM32=arm-linux-androideabi- \
                            CLANG_TRIPLE=aarch64-linux-gnu-
}

# End with success or fail
End() {
    if [ -e $MainPath/out/arch/arm64/boot/Image.gz-dtb ]; then
        BUILD_END=$(date +"%s")
        DIFF=$((BUILD_END - BUILD_START))
        MakeZip
        ZIP=$(echo *$Compiler*$TIME*.zip)
        if [ $UT = 1 ]; then
            TIME=$(echo "Build success in : $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)")
            FILE=$ZIP
            Caption="$TIME @OVERThinkingBABY"
            Upload
        else
            echo "Build success in : $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)"
        fi
    else
        BUILD_END=$(date +"%s")
        DIFF=$((BUILD_END - BUILD_START))
        if [ $UT = 1 ]; then
            TIME=$(echo "Build fail in : $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)")
            FILE="out/error.log"
            Caption="$TIME Check this @OVERThinkingBABY"
            Upload
        else
            echo "Build fail in : $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)"
        fi
    fi
}

Text="Start to build kernel"

# Build choices
GCC() {
    if [ $UT = 1 ]; then
        msg
    fi
    Clone_GCC
    Build_GCC
    End
}

Proton() {
    if [ $UT = 1 ]; then
        msg
    fi
    Clone_Proton
    Build_Proton
    End
}

DTC() {
    if [ $UT = 1 ]; then
        msg
    fi
    Clone_DTC
    Build_DTC
    End
}
