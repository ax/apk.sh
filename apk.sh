#!/bin/bash
#
# apk.sh v1.0.8
# author: ax - github.com/ax
#
# -----------------------------------------------------------------------------
#
# SYNOPSIS
#	apk.sh [SUBCOMMAND] [APK FILE|APK DIR|PKG NAME] [FLAGS]
#	apk.sh pull [PKG NAME] [FLAGS]
#	apk.sh decode [APK FILE] [FLAGS]
#	apk.sh build [APK DIR] [FLAGS]
#	apk.sh patch [APK FILE] [FLAGS]
#	apk.sh rename [APK FILE] [PKG NAME] [FLAGS]
#
# SUBCOMMANDS
#	pull	Pull an apk from device/emulator.
#	decode	Decode an apk.
#	build	Re-build an apk.
#	patch	Patch an apk.
#	rename	Rename the apk package.
#
# FLAGS
#	-a, --arch <arch>	Specify the target architecture, mandatory when patching.
#
#	-g, --gadget-conf <json_file>	
#				Specify a frida-gadget configuration file, optional when patching.
#
#	-n, --net		Add a permissing network security config when building, optional.
#				It can be used with patch, pull and rename also.
#
#	-s, --safe		Do not decode resources when decoding (i.e. apktool -r).
#				Cannot be used when patching.
#
#	-d, --no-dis		Do not disassemble dex, optional when decoding (i.e. apktool -s).
#				Cannot be used when patching.
#
# -----------------------------------------------------------------------------
#

VERSION="1.0.8"
echo -e "[*] \033[1mapk.sh v$VERSION \033[0m"

APK_SH_HOME="${HOME}/.apk.sh"
mkdir -p $APK_SH_HOME
echo "[*] home dir is $APK_SH_HOME"

supported_arch=("arm" "x86_64" "x86" "arm64")

print_(){
	:
	#echo $1
}
print_ "[*] DEBUG is TRUE"

APKTOOL_VER=`wget https://api.github.com/repos/iBotPeaches/Apktool/releases/latest -q -O - | grep -Po "tag_name\": \"v\K.*?(?=\")"`
APKTOOL_PATH="$APK_SH_HOME/apktool_$APKTOOL_VER.jar"

BUILDTOOLS_VER="33.0.1"
SDK_ROOT="$APK_SH_HOME/sdk_root"
BUILD_TOOLS="$SDK_ROOT/build-tools/$BUILDTOOLS_VER"
PLATFORM_TOOLS="$SDK_ROOT/platform-tools"


if [ ! -d "$BUILD_TOOLS" ]; then
	APKSIGNER="apksigner"
	ZIPALIGN="zipalign"
	AAPT="aapt"
else
	APKSIGNER="$BUILD_TOOLS/apksigner"
	ZIPALIGN="$BUILD_TOOLS/zipalign"
	AAPT="$BUILD_TOOLS/aapt"
fi
if [ ! -d "$PLATFORM_TOOLS" ]; then
        ADB="adb"
else
        ADB="$PLATFORM_TOOLS/adb"
fi

CMDLINE_TOOLS_DIR="$APK_SH_HOME/cmdline-tools"

install_cmdlinetools() {
	CMDLINE_TOOLS_DOWNLOAD_URL="https://dl.google.com/android/repository/commandlinetools-linux-9123335_latest.zip"
        echo "[>] Downloading Android commandline tools from $CMDLINE_TOOLS_DOWNLOAD_URL"
        wget $CMDLINE_TOOLS_DOWNLOAD_URL -q --show-progress -P $APK_SH_HOME
        unzip $APK_SH_HOME/commandlinetools-linux-9123335_latest.zip -d $APK_SH_HOME
        rm $APK_SH_HOME/commandlinetools-linux-9123335_latest.zip
	echo "[>] Done!"
}

install_buildtools(){
	if [ ! -d "$CMDLINE_TOOLS_DIR" ]; then
		install_cmdlinetools
	fi
	SDK_MANAGER_BIN="$CMDLINE_TOOLS_DIR/bin/sdkmanager"
	mkdir -p $SDK_ROOT
	INSTALL_BUILDTOOLS_CMD="echo -ne 'y\n' | $SDK_MANAGER_BIN 'build-tools;$BUILDTOOLS_VER' --sdk_root=$SDK_ROOT"
	echo -e "[>] Installing build-tools $BUILDTOOLS_VER..."
	run "$INSTALL_BUILDTOOLS_CMD"
	APKSIGNER="$BUILD_TOOLS/apksigner"
	ZIPALIGN="$BUILD_TOOLS/zipalign"
	AAPT="$BUILD_TOOLS/aapt"
	echo "[>] Done!"
}

install_platformtools(){
	if [ ! -d "$CMDLINE_TOOLS_DIR" ]; then
                install_cmdlinetools
        fi
        SDK_MANAGER_BIN="$CMDLINE_TOOLS_DIR/bin/sdkmanager"
        mkdir -p $SDK_ROOT
	INSTALL_PLATFORMTOOLS_CMD="echo -ne 'y\n' | $SDK_MANAGER_BIN 'platform-tools' --sdk_root=$SDK_ROOT"
        echo -e "[>] Installing platform-tools ..."
	run "$INSTALL_PLATFORMTOOLS_CMD"
        ADB="$PLATFORM_TOOLS/adb"
	echo "[>] Done!"
}


check_apk_tools(){
	if [ -f "$APKTOOL_PATH" ]; then
		echo "[*] apktool v$APKTOOL_VER exist in $APK_SH_HOME"
	else
		APKTOOL_DOWNLOAD_URL_BB="https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_$APKTOOL_VER.jar"
		APKTOOL_DOWNLOAD_URL_GH="https://github.com/iBotPeaches/Apktool/releases/download/v$APKTOOL_VER/apktool_$APKTOOL_VER.jar"
		APKTOOL_DOWNLOAD_URL=$APKTOOL_DOWNLOAD_URL_GH
		echo "[!] No apktool v$APKTOOL_VER found!"
		echo "[>] Downloading apktool from $APKTOOL_DOWNLOAD_URL"
		wget $APKTOOL_DOWNLOAD_URL -q --show-progress -P $APK_SH_HOME 
	fi
	if  is_not_installed 'apksigner'; then
		if [ ! -f "$APKSIGNER" ]; then
			echo "[!] No apksigner found in path!"
			echo "[!] No apksigner found in $APK_SH_HOME"
			install_buildtools
			echo "[>] apksigner installed!"
		else
			echo "[*] apksigner v`$APKSIGNER --version` exist in $BUILD_TOOLS"
		fi
	fi
	if  is_not_installed 'zipalign'; then
		if [ ! -f "$ZIPALIGN" ]; then
			install_buildtools
			echo "[>] zipalign installed!"
		else
			echo "[*] zipalign exist in $BUILD_TOOLS"
		fi
	fi
	if  is_not_installed 'aapt'; then
		if [ ! -f "$AAPT" ]; then
			install_buildtools
			echo "[>] aapt installed!"
		else
			echo "[*] aapt exist in $BUILD_TOOLS"
		fi
	fi
	if  is_not_installed 'adb'; then
                if [ ! -f "$ADB" ]; then
                        install_platformtools
                        echo "[>] adb installed!"
                else
                        echo "[*] adb exist in $PLATFORM_TOOLS"
                fi
        fi
	if  is_not_installed 'unxz'; then
		echo "[>] No unxz found!"
		echo "[>] Pls install unxz!"
		exit 1
	fi
	if  is_not_installed 'unzip'; then
		echo "[>] No unzip found!"
		echo "[>] Pls install unzip!"
		exit 1
	fi
	return 0
}

is_not_installed() {
	if [ -z `command -v $1 2>/dev/null` ]; then
		return 0
	fi
		return 1
}

run(){
	if ! eval "$1"; then
		echo "[>] Sorry!"
		echo "[!] $1 return errors!"
		echo "[>] Bye!"
		exit 1
	fi
}

exit_if_not_exist(){
	if [ ! -f "$1" ]; then
		if [ ! -d "$1" ]; then
		echo "[!] File $1 not found!"
		echo "[>] Bye!"
		exit 1
		fi
	fi
}


apk_decode(){
	APK_NAME="$1"
	DECODE_CMD_OPTS="$2"
	DECODE_CMD_START="java -jar $APKTOOL_PATH d"
	DECODE_CMD="$DECODE_CMD_START $APK_NAME $DECODE_CMD_OPTS"
	echo -e "[>] \033[1mDecoding $APK_NAME\033[0m with $DECODE_CMD"
	run "$DECODE_CMD"
	echo "[>] Done!"
}


apk_build(){
	APK_DIR="$1"
	BUILD_CMD_OPTS="$2"
	BUILD_CMD_START="java -jar $APKTOOL_PATH b -d "
	BUILD_CMD="$BUILD_CMD_START $APK_DIR $BUILD_CMD_OPTS"
	APK_NAME=`echo $BUILD_CMD_OPTS | grep -Po "\-o \K.*?(?= )"`
	if [ -z $APK_NAME ]; then
		APK_NAME="$APK_DIR.apk"
	fi
	if [[ "$BUILD_CMD_OPTS" == *" -n "* || "$BUILD_CMD_OPTS" == *" -n" ]]; then
		mkdir -p "$APK_DIR/res/xml"
	fi
	echo -e "[>] \033[1mBuilding\033[0m with $BUILD_CMD"
	run "$BUILD_CMD"
	echo "[>] Built!"
	echo "[>] Aligning with zipalign -p 4 ...."
	run "$ZIPALIGN -p 4 $APK_NAME $APK_NAME-aligned.apk"
	echo "[>] Done!"

	KS="$APK_SH_HOME/my-new.keystore"
	if [ ! -f "$KS" ]; then
		echo "[!] Keystore does not exist!"
		echo "[>] Generating keystore..."
		keytool -genkey -v -keystore $KS -alias alias_name -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -noprompt -dname "CN=noway, OU=ID, O=Org, L=Blabla, S=Blabla, C=US"
	else
		echo "[>] A Keystore exist!"
	fi
	echo "[>] Signing $APK_NAME with apksigner..."
	$APKSIGNER sign --ks $KS --ks-pass pass:password "$APK_NAME-aligned.apk"
	#jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-new.keystore -storepass "password" file.apk alias_name
	rm $APK_NAME
	mv "$APK_NAME-aligned.apk" "$APK_NAME"
	echo "[>] Done!"
	echo "[>] $APK_NAME ready!"
	return 0
}


apk_patch(){
	# Frida gadget exposes a frida-server compatible interface, listening on localhost:27042 by default.
	# run as soon as possible: frida -D emulator-5554 -n Gadget

	APK_NAME=$1
	ARCH=$2
	GADGET_CONF_PATH=$3
	BUILD_OPTS=$4

	arm=("armeabi" "armeabi-v7a")
	arm64=("arm64-v8a" "arm64")
	x86=("x86")
	x86_64=("x86_64")
	GADGET_VER=`wget https://api.github.com/repos/frida/frida/releases/latest -q -O - | grep -Po "tag_name\": \"\K.*?(?=\")"`
	GADGET_ARM="frida-gadget-$GADGET_VER-android-arm.so.xz"
	GADGET_ARM64="frida-gadget-$GADGET_VER-android-arm64.so.xz"
	GADGET_X86_64="frida-gadget-$GADGET_VER-android-x86_64.so.xz"
	GADGET_X86="frida-gadget-$GADGET_VER-android-x86.so.xz"
	#GADGET_X86_64="frida-gadget-15.2.2-android-x86_64.so.xz"

	#  folder:arch
	#  'armeabi': 'arm',
	#  'armeabi-v7a': 'arm',
    #  'arm64': 'arm64',
    #  'arm64-v8a': 'arm64',
    #  'x86': 'x86',
	#  'x86_64': 'x86_64',

	echo -e "[>] \033[1mPatching $APK_NAME injecting gadget for $ARCH...\033[0m"

	if [[ ${ARCH} == "arm"  ]]; then
		GADGET=$GADGET_ARM
		ARCH_DIR="armeabi-v7a"
	elif [[ ${ARCH} == "x86_64" ]]; then
		GADGET=$GADGET_X86_64
		ARCH_DIR="x86_64"
	elif [[ ${ARCH} == "x86" ]]; then
		GADGET=$GADGET_X86
		ARCH_DIR="x86"
	elif [[ ${ARCH} == "arm64" ]]; then
		GADGET=$GADGET_ARM64
		ARCH_DIR="arm64-v8a"
	fi

	FRIDA_SO_XZ="$APK_SH_HOME/$GADGET"
	FRIDA_SO="${FRIDA_SO_XZ%???}" # bash 3.x compliant xD

	if [ ! -f "$FRIDA_SO" ]; then
		if [ ! -f "$FRIDA_SO_XZ" ]; then
			echo "[!] Frida gadget not present in $APK_SH_HOME"
			echo "[>] Downloading latest frida gadget for $ARCH from github.com..."
			wget https://github.com/frida/frida/releases/download/$GADGET_VER/$GADGET -q --show-progress -P $APK_SH_HOME 
		fi
		unxz "$FRIDA_SO_XZ"
	else
		echo "[>] Frida gadget already present in $APK_SH_HOME"
	fi
	echo "[>] Using $FRIDA_SO"

	APKTOOL_DECODE_OPTS=""
	apk_decode "$APK_NAME" "$APKTOOL_DECODE_OPTS"

	echo -e "[>] \033[1mInjecting Frida gadget...\033[0m"
	echo "[>] Placing the Frida shared object for $ARCH...."
	APK_DIR=${APK_NAME%.apk} # bash 3.x compliant xD
	mkdir -p "$APK_DIR/lib/$ARCH_DIR/"
	cp ${FRIDA_SO_XZ::-3} $APK_DIR/lib/$ARCH_DIR/libfrida-gadget.so
	if [ ! -z $GADGET_CONF_PATH ]; then
		echo "[>] Placing the specified gadget configuration json file...."
		cp "$GADGET_CONF_PATH" $APK_DIR/lib/$ARCH_DIR/libfrida-gadget.config.so
	fi

	# Inject a System.loadLibrary("frida-gadget") call into the smali,
	# before any other bytecode executes or any native code is loaded.
	# A suitable place is typically the static initializer of the entry point class of the app (e.g. the main application Activity).
	# We have to determine the class name for the activity that is launched on application startup.
	# In Objection this is done by first trying to parse the output of aapt dump badging, then falling back to manually parsing the AndroidManifest for activity-alias tags.
	echo "[>] Searching for a launchable-activity..."
	MAIN_ACTIVITY=`$AAPT dump badging $APK_NAME | grep launchable-activity | grep -Po "name='\K.*?(?=')"`
	echo "[>] launchable-activity found --> $MAIN_ACTIVITY"
	# TODO: If we dont get the activity, we gonna check out activity aliases trying to manually parse the AndroidManifest.
	# Try to determine the local path for a target class' smali converting the main activity to a path
	MAIN_ACTIVITY_2PATH=`echo $MAIN_ACTIVITY | tr '.' '/'`
	CLASS_PATH="./$APK_DIR/smali/$MAIN_ACTIVITY_2PATH.smali"
	echo "[>] Local path should be $CLASS_PATH"
	# NOTE: if the class does not exist it might be a multidex setup.
	# Search the class in smali_classesN directories. 
	CLASS_PATH_IND=1 # starts from 2
	# get max number of smali_classes
    CLASS_PATH_IND_MAX=$(ls -1 "./$APK_DIR" | grep "_classes[0-9]*" | wc -l)
	while [ ! -f "$CLASS_PATH" ]
	do
		echo "[!] $CLASS_PATH does not exist! Probably a multidex APK..."
		if [ $CLASS_PATH_IND -gt $CLASS_PATH_IND_MAX ]; then
			# keep searching until smali_classesN then exit
			echo "[>] $CLASS_PATH NOT FOUND!"
			echo "[!] Can't find the launchable-activity! Sorry."
			echo "[>] Bye!"
			exit 1
		fi
		CLASS_PATH_IND=$((CLASS_PATH_IND+1))
		 # ./base/smali/
		 # ./base/smali_classes2/
		CLASS_PATH="./$APK_DIR/smali_classes$CLASS_PATH_IND/$MAIN_ACTIVITY_2PATH.smali"
		echo "[?] Looking in $CLASS_PATH..."
	done
	
	#
	# Now, patch the smali, look for the line with the apktool's comment "# direct methods" 
	# Patch the smali with the appropriate loadLibrary call based on wether a constructor already exists or not.
	# If an existing constructor is present, the partial_load_library will be used.
	# If no constructor is present, the full_load_library will be used.
	#
	# Objection checks if there is an existing <clinit> to determine which is the constructor,
	# then they inject a loadLibrary just before the method end.
	#
	# We search for *init> and inject a loadLibrary just after the .locals declaration.
	#
	# <init> is the (or one of the) constructor(s) for the instance, and non-static field initialization.
	# <clinit> are the static initialization blocks for the class, and static field initialization.
	#
	echo "[>] $CLASS_PATH found!"
	echo "[>] Patching smali..."
	readarray -t lines < $CLASS_PATH
	index=0
	skip=1
	for i in "${lines[@]}"
	do
		# partial_load_library
		if [[ $i == "# direct methods" ]]; then
			if [[   ${lines[$index+1]} == *"init>"* ]]; then
				echo "[>>] A constructor is already present --> ${lines[$index+1]}"
				echo "[>>] Injecting partial load library!"
				# Skip  any .locals and write after
				# Do we have to skip .annotaions? is ok to write before them?
				if [[ ${lines[$index+2]} =~ \.locals* ]]; then
					echo "[>>] .locals declaration found!"
					echo "[>>] Skipping .locals line..."
					skip=2
					echo "[>>] Update locals count..."
					locals=`echo ${lines[$index+2]} | cut -d' ' -f2`
					((locals++))
					lines[$index+2]=".locals $locals"
				else
					echo "[!!!!!!] No .locals found! :("
					echo "[!!!!!!] TODO add .locals line"
				fi
				arr=("${lines[@]:0:$index+1+$skip}") 			# start of the array
				# We inject a loadLibrary just after the locals delcaration.
				# Objection add the loadLibrary call just before the method end.
				arr+=( 'const-string v0, "frida-gadget"')
				arr+=( 'invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V')
				arr+=( "${lines[@]:$index+1+$skip}" ) 		# tail of the array
        		lines=("${arr[@]}")     					# transfer back in the original array.
			else
				echo "[!!!!!!] No constructor found!"
				echo "[!!!!!!] TODO: gonna use the full load library"
				#arr+=('.method static constructor <clinit>()V')
				#arr+=('   .locals 1')
				#arr+=('')
				#arr+=('   .prologue')
				#arr+=('   const-string v0, "frida-gadget"')
				#arr+=('')
				#arr+=('   invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V')
				#arr+=('')
				#arr+=('   return-void')
				#arr+=('.end method')
			fi
		fi
		((index++))
	done
	echo "[>] Writing the pathced smali back..."
	printf "%s\n" "${lines[@]}" > $CLASS_PATH
	
	# Add the Internet permission to the manifest if it’s not there already, to permit Frida gadget to open a socket.
	echo "[?] Checking if Internet permission is present in the manifest..."
	INTERNET_PERMISSION=0
	MANIFEST_PATH="$APK_DIR/AndroidManifest.xml"
	readarray -t manifest < $MANIFEST_PATH
	for i in "${manifest[@]}"
	do
		if [[ "$i" == *"<uses-permission android:name=\"android.permission.INTERNET\"/>"* ]]; then
			INTERNET_PERMISSION=1
			echo "[>] Internet permission is there!"
			break
		fi
	done
	if [[ $INTERNET_PERMISSION == 0 ]]; then
		echo "[!] Internet permission not present in the Manifest!"
		echo "[>] Patching $MANIFEST_PATH"
		arr=("${manifest[@]:0:1}") 			# start of the array
		arr+=( '<uses-permission android:name="android.permission.INTERNET"/>')
		arr+=( "${manifest[@]:1}" ) 		# tail of the array
        manifest=("${arr[@]}")     		# transfer back in the original array.
		echo "[>] Writing the patched manifest back..."
		printf "%s\n" "${manifest[@]}" > $MANIFEST_PATH
	fi


	APKTOOL_BUILD_OPTS="-o $APK_DIR.gadget.apk --use-aapt2"
	APKTOOL_BUILD_OPTS="$APKTOOL_BUILD_OPTS $BUILD_OPTS"
	apk_build "$APK_DIR" "$APKTOOL_BUILD_OPTS"
	echo "[>] Bye!"
	return 0;
}

apk_pull(){
	PACKAGE=$1
	BUILD_OPTS=$2
	PACKAGE_PATH=`$ADB shell pm path "$PACKAGE" | sed 's/\r//' | cut -d ":" -f 2`

	if [ -z "$PACKAGE_PATH" ]; then
		echo "[>] Sorry, cant find package $PACKAGE"
		echo "[>] Bye!"
		exit 1
	fi
	NUM_APK=`echo "$PACKAGE_PATH" | wc -l`
	if [ $NUM_APK -gt 1 ]; then
		SPLIT_DIR=$PACKAGE"_split_apks"
		mkdir -p $SPLIT_DIR 
		echo "[>] Pulling $PACKAGE: Split apks detected!"
		echo "[>] Pulling $NUM_APK apks in ./$SPLIT_DIR/"
		print_ "[>] Pulling $PACKAGE from $PACKAGE_PATH<<<"

		for P in $PACKAGE_PATH
		do
			PULL_CMD="$ADB pull $P $SPLIT_DIR"
			run "$PULL_CMD"
		done
		# We have to combine split APKs into a single APK, for patching. 
		# Decode all the APKs.
		echo "[>] Combining split APKs into a single APK..."
		SPLIT_APKS=($SPLIT_DIR/*)
		for i in "${SPLIT_APKS[@]}"
		do
			print_ $i
			APK_NAME=$i
			APK_DIR=${APK_NAME%.apk} # bash 3.x compliant xD
			APKTOOL_DECODE_OPTS="--resource-mode dummy -o $APK_DIR 1>/dev/null"
			apk_decode "$APK_NAME" "$APKTOOL_DECODE_OPTS"
		done
		# Walk the extracted APKs dirs and copy files and dirs to the base APK dir. 
		echo "[>] Walking extracted APKs dirs and copying files to the base APK..."
		for i in "${SPLIT_APKS[@]}"
		do
			APK_NAME=$i
			APK_DIR=${APK_NAME%.apk} # bash 3.x compliant xD

			# Skip base.apk.
			if [ $APK_DIR == $SPLIT_DIR"/base" ]; then
				continue
			fi
			# Walk each apk dir.
			FILES_IN_SPLIT_APK=($APK_DIR/*)
			for j in "${FILES_IN_SPLIT_APK[@]}"
			do
				print_ "[>>>>] Parsing split apks file: "$j
				# Skip Manifest, apktool.yml, and the original files dir.
				if [[ $j == *AndroidManifest.xml ]] || [[ $j == *apktool.yml ]] || [[ $j == *original ]]; then
					print_ "[-] Skip!"
					continue
				fi
				# Copy files into the base APK, except for XML files in the res directory
				if [[ $j == */res ]]; then
					print_ "[.] /res direcorty found!":
					(cd $j; find . -type f ! -name '*.xml' -exec cp --parents {} ../../base/res/ \;)# -exec echo '[+] Copying res that are not xml {}'\;)    
					continue
				fi
				print_ "[>] Copying directory cp -R $j in $SPLIT_DIR/base/ ...."
				cp -R $j $SPLIT_DIR"/base/"
			done
		done
		echo "[>] Fixing APKTOOL_DUMMY public resource identifiers..."
		echo "[>] - Find all public DUMMY_NAME/REAL_NAME pairs ..."

		# Fix public resource identifiers. 
		# Find all resource IDs with name APKTOOOL_DUMMY_xxx in the base dir
		DUMMY_IDS=`grep "APKTOOL_DUMMY_" $SPLIT_DIR"/base/res/values/public.xml" | grep -Po "id=\"\K.*?(?=\")" | grep 0x`
		stra=($DUMMY_IDS)
		ITER=1
		TOTAL=${#stra[@]}
		touch $SPLIT_DIR"/DUMMY_REPLACEMENT.txt"
		for j in "${stra[@]}"
		do
			print_ "[~] ("$ITER"/"$TOTAL") DUMMY_ID_TO_FIX: "$j
			# Get the dummy name grepping for the resource ID
			DUMMY_NAME=`grep "$j" $SPLIT_DIR/base/res/values/public.xml | grep DUMMY | grep -Po "name=\"\K.*?(?=\")"`
			print_ "[~] ("$ITER"/"$TOTAL") DUMMY_NAME: "$DUMMY_NAME
			# Get the real resource name grepping for the resource ID in each spit APK
			REAL_NAME=`grep "$j" $SPLIT_DIR/*/res/values/public.xml | grep -v DUMMY | grep -v base | grep name | grep -Po "name=\"\K.*?(?=\")"`
			print_ "[~] ("$ITER"/"$TOTAL") REAL_NAME: "$REAL_NAME
			echo "s/\<$DUMMY_NAME\>/$REAL_NAME/g" >> $SPLIT_DIR"/DUMMY_REPLACEMENT.txt"
			print_ "---"
			ITER=$(expr $ITER + 1)
		done
		echo "[>] - Replace DUMMY_NAME/REAL_NAME in all base.apk xml files containing APKTOOL_DUMMY_"
		grep -rl "APKTOOL_DUMMY_" --include "*\.xml" $SPLIT_DIR"/base" | xargs sed -i -f $SPLIT_DIR"/DUMMY_REPLACEMENT.txt"
		rm $SPLIT_DIR"/DUMMY_REPLACEMENT.txt"
		echo "[>] Done!"

		# Disable APK splitting in the base manifest file, if it’s not there already done.        
		MANIFEST_PATH="$SPLIT_DIR/base/AndroidManifest.xml"
		echo "[>] Disabling APK splitting :"
  		echo "[>] - Make sure isSplitRequired is set to false"
		sed -i "s/android:isSplitRequired=\"true\"/android:isSplitRequired=\"false\"/g" $MANIFEST_PATH
  		echo "[>] - Make sure com.android.vending.splits.required is set to false"
  		sed -i "/com.android.vending.splits.required/s/true/false/g" $MANIFEST_PATH
		echo "[>] Done!"
		#	Set android:extractNativeLibs="true" in the Manifest if you experience any adb: failed to install file.gadget.apk:
		#	Failure [INSTALL_FAILED_INVALID_APK: Failed to extract native libraries, res=-2]
		echo "[>] Enabling native libraries extraction if it was set to false..."
		# If the tag exist and is set to false, set it to true, otherwise do nothing
		sed -i "s/android:extractNativeLibs=\"false\"/android:extractNativeLibs=\"true\"/g" $MANIFEST_PATH
		echo "[>] Done!"
		# Rebuild the base APK 
		APKTOOL_BUILD_OPTS="-o file.single.apk --use-aapt2"
		APKTOOL_BUILD_OPTS="$APKTOOL_BUILD_OPTS $BUILD_OPTS"
		apk_build "$SPLIT_DIR/base" "$APKTOOL_BUILD_OPTS"
		echo "[>] Bye!"
		return 0
	else
		echo "[>] Pulling $PACKAGE from $PACKAGE_PATH"
		PULL_CMD="$ADB pull $PACKAGE_PATH ."
		run "$PULL_CMD"
		echo "[>] Done!"
		echo "[>] Bye!"
		return 0
	fi
}

apk_rename(){
	APK_NAME=$1
	PACKAGE=$2
	BUILD_OPTS=$3
	echo -e "[>] \033[1mRenaming $APK_NAME\033[0m to $PACKAGE"
	APKTOOL_DECODE_OPTS="1>/dev/null"
	apk_decode "$APK_NAME" "$APKTOOL_DECODE_OPTS"
	APK_DIR=${APK_NAME%.apk} # bash 3.x compliant xD
	APKTOOL_YML_PATH="$APK_DIR/apktool.yml"
	echo "[>] Updating renameManifestPackage in apktool.yml with $PACKAGE"
	# Note: https://github.com/iBotPeaches/Apktool/issues/1753
	# renameManifestPackage is not designed for manual package name changes, but can be useful in some situations.
	sed -i "s/renameManifestPackage:.*/renameManifestPackage: $PACKAGE/g" $APKTOOL_YML_PATH
	APKTOOL_BUILD_OPTS="-o file.renamed.apk --use-aapt2"
	APKTOOL_BUILD_OPTS="$APKTOOL_BUILD_OPTS $BUILD_OPTS"
	# Silently build
	apk_build "$APK_DIR" "$APKTOOL_BUILD_OPTS 1>/dev/null"
	return 0;
}

#####################################################################
#####################################################################

check_apk_tools 

if [ ! -z $1 ]&&[ $1 == "build" ]; then
	if [ -z "$2" ]; then
    	echo "Pass the apk directory name!"
    	echo "./apk build <apk_dir>"
		exit 1
	fi
	#	
	# It seems there is a problem with apktool build and manifest attribute android:dataExtractionRules 
	# 	: /home/ax/AndroidManifest.xml:30: error: attribute android:dataExtractionRules not found.
	# 	W: error: failed processing manifest.
	# Temporary workaround: remove the attribute from the Manifest and use Android 9 
	#
	# Set android:extractNativeLibs="true" in the Manifest if you experience any adb:
	# failed to install file.gadget.apk: Failure [INSTALL_FAILED_INVALID_APK: Failed to extract native libraries, res=-2]
	# https://github.com/iBotPeaches/Apktool/issues/1626 - zipalign -p 4 seems to not resolve the issue.
	#
	APK_DIR=$2
	exit_if_not_exist "$APK_DIR"
	APKTOOL_BUILD_OPTS="-o file.apk --use-aapt2"
	#APKTOOL_BUILD_OPTS="--use-aapt2"
	shift # pop SUBCOMMAND
	shift # pop SUBCOMMAND_ARG
	while [[ $# -gt 0 ]]; do
	  case $1 in
		-n|--net)
		  APKTOOL_BUILD_OPTS="$APKTOOL_BUILD_OPTS -n"
		  shift # arg
		  ;;
		-*|--*)
		  echo "[!] Unknown option $1"
		  exit 1
		  ;;
		*)
		  POSITIONAL_ARGS+=("$1") # save positional arg
		  shift # arg
		  ;;
	  esac
	done
	apk_build "$APK_DIR" "$APKTOOL_BUILD_OPTS"
	exit 0

elif [ ! -z $1 ]&&[ $1 == "decode" ]; then
	if [ -z "$2" ]; then
    	echo "Pass the apk name!"
    	echo "./apk decode <apkname.apk>"
		exit 1
	fi
	APK_NAME=$2
	exit_if_not_exist "$APK_NAME"
	APKTOOL_DECODE_OPTS=""
	shift # pop SUBCOMMAND
	shift # pop SUBCOMMAND_ARG
	while [[ $# -gt 0 ]]; do
		case $1 in
			-s|--safe)
		  		APKTOOL_DECODE_OPTS="$APKTOOL_DECODE_OPTS -r" # no decode res
				shift # arg
		  	;;
			-d|--no-dis)
		  		APKTOOL_DECODE_OPTS="$APKTOOL_DECODE_OPTS -s" # no disass dex
				shift # argument
		  	;;
			-*|--*)
		  		echo "[!] Unknown option $1"
		  		exit 1
		  	;;
			*)
		  		POSITIONAL_ARGS+=("$1") # save positional arg
		  		shift # arg
		  	;;
		esac
	done
	apk_decode "$APK_NAME" "$APKTOOL_DECODE_OPTS"
	exit 0

elif [ ! -z $1 ]&&[ $1 == "patch" ]; then
	if [ -z "$2" ]; then
    	echo "Pass the apk name and the arch param!"
    	echo "./apk patch <apkname.apk> --arch arm"
		echo "[>] Bye!"
		exit 1
	fi
	APK_NAME=$2
	APKTOOL_BUILD_OPTS=""
	GADGET_CONF_PATH=""
	exit_if_not_exist "$APK_NAME"
	shift # pop SUBCOMMAND
	shift # pop SUBCOMMAND_ARG
	while [[ $# -gt 0 ]]; do
		case $1 in
			-a|--arch)
				# what if $2 not exist
		  		ARCH="$2"
				shift # arg
		  		shift # val
		  	;;
			-g|--gadget-conf)
				GADGET_CONF_PATH="$2"
				exit_if_not_exist "$GADGET_CONF_PATH"
				shift # argument
		  		shift # value
		  	;;
			-n|--net)
		  		APKTOOL_BUILD_OPTS="$APKTOOL_BUILD_OPTS -n"
		  		shift # argument
		  	;;
			-*|--*)
		  		echo "[!] Unknown option $1"
		  		exit 1
		  	;;
			*)
		  		POSITIONAL_ARGS+=("$1") # save positional arg
		  		shift # argument
		  	;;
		esac
	done
	if [ -z "$ARCH" ]; then
		echo "[!] Pass the --arch param with a supported arch"
    	echo "./apk patch <apkname.apk> --arch arm"
		echo "[>] Bye!"
		exit 1
	fi
	if [[ ! "${supported_arch[*]}" =~ "${ARCH}" ]]; then
		echo "[!] Architecture not supported!"
		echo "[>] Bye!"
		exit 1
	fi
	apk_patch "$APK_NAME" "$ARCH" "$GADGET_CONF_PATH" "$APKTOOL_BUILD_OPTS"
	exit 0

elif [ ! -z $1 ]&&[ $1 == "pull" ]; then
	if [ -z "$2" ]; then
    	echo "Pass the package name!"
    	echo "./apk pull <com.package.name>"
		exit 1
	fi
	PACKAGE_NAME=$2
	APKTOOL_BUILD_OPTS=""
	if [ ! -z "$3" ]&&[ "$3" == "--net" ]; then
		APKTOOL_BUILD_OPTS="$APKTOOL_BUILD_OPTS -n"
	fi
	apk_pull "$PACKAGE_NAME" "$APKTOOL_BUILD_OPTS"

elif [ ! -z $1 ]&&[ $1 == "rename" ]; then
	if [ -z "$2" ]; then
    	echo "Pass the apk name!"
    	echo "./apk rename <apkname.apk> <com.package.name>"
		exit 1
	fi
	APK_NAME=$2
	exit_if_not_exist "$APK_NAME"
	if [ -z "$3" ]; then
    	echo "Pass the package name"
    	echo "./apk rename <apkname.apk> <com.package.name>"
		echo "[>] Bye!"
		exit 1
	fi
	PACKAGE_NAME=$3
	APKTOOL_BUILD_OPTS=""
	if [ ! -z "$4" ]&&[ "$4" == "--net" ]; then
		APKTOOL_BUILD_OPTS="$APKTOOL_BUILD_OPTS -n"
	fi
	apk_rename "$APK_NAME" "$PACKAGE_NAME" "$APKTOOL_BUILD_OPTS"
	exit 0

else
	echo "[!] First arg must be build, decode, pull, rename or patch!"
    echo " ./apk.sh pull <package_name>"
	echo " ./apk.sh decode <apk_file>"
    echo " ./apk.sh build <apk_dir>"
	echo " ./apk.sh patch <apk_file> --arch arm"
    echo " ./apk.sh rename <apk_file> <package_name>"
	echo "[>] Bye!"
	exit 1
fi
