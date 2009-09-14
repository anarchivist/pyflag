#!/bin/bash
# ubuntu_forensic_installer.sh install script
# version 2-20080302
# by J. Lehr, slo.sleuth@gmail.com

#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

##### Script Information

# This script is intended to be used with a default Ubuntu install disc
# to install packages and build source code that supports the PyFLAG
# forensic environment.
#
# The script can be used in two ways:
# 
# 1) Where the installation computer has 2gb or more of RAM, this script
# can be executed in the Ubuntu-live environment.  After completion, the
# Ubuntu installer can be used to install the PyFLAG enabled distri-
# bution to hard disk, usb device, etc.
#
# 2) Where the installation computer has less than 2gb of RAM, this
# script can be run AFTER the Ubuntu installer from within the newly
# installed operating system.


##### Constants

DL_DIR=$HOME/forensics # Directory to hold downloaded forensic tools

# To update script, replace variables with latest program information.
LIBEWF=libewf-20080501
LIBEWF_URL="http://sourceforge.net/projects/libewf/files/libewf/$LIBEWF/$LIBEWF.tar.gz/download"
LIBEWF_DEPS="zlib1g-dev uuid-dev libssl-dev"

AFFLIB=afflib-3.3.4
AFFLIB_URL="-nc http://www.afflib.org/downloads/$AFFLIB.tar.gz"
AFFLIB_DEPS="libtool libreadline5-dev libncurses5-dev libexpat1-dev libfuse-dev"

AIMAGE=aimage-3.2.0
AIMAGE_URL="-nc http://www.afflib.org/downloads/$AIMAGE.tar.gz"
AIMAGE_DEPS=""

TSK=sleuthkit-3.0.1
TSK_URL="-nc http://superb-east.dl.sourceforge.net/sourceforge/sleuthkit/$TSK.tar.gz"
TSK_DEPS=""

PYFLAG=pyflag
PYFLAG_URL="http://pyflag.net/pyflag"
PYFLAG_DEPS="darcs python-dev python-mysqldb libmagic-dev python-imaging python-pexpect python-dateutil python-urwid python-crypto python-pyparsing python-sqlite mysql-server libgeoip-dev libjpeg62-dev clamav-daemon"


##### Main Installation

# Ensure script is run as root.
if [ "$(id -ru)" != "0" ]
	then echo "\nYou must be superuser to run this script.\a" >&2; exit 1
fi
	

# Print script title/disclaimer.
clear
cat << EOF
****************************************
* Ubuntu Forensic Installer for PyFLAG *
****************************************

Disclaimer:

This script installs the PyFLAG forensic software in an Ubuntu Linux
distribution.  It DOES NOT currently configure Ubuntu for live analysis,
though it is suitable for analysis of disk images.

Forensic environment configuration will be incorporated in future 
versions.

Press ctrl-c to quit, or Enter to continue: 
EOF
read keypress
clear


# Create Ubuntu build environment and install package dependencies (required for installing forensic programs).
echo "Updating sources list... please wait."
cp /etc/apt/sources.list /etc/apt/sources.list.backup # Backup existing sources list.
sed -i -e "s/# deb/deb/g" /etc/apt/sources.list # Uncomment required sources to make them available.
apt-get -qq update 
echo "Updated!\n"


# Set "pyflag" as mysql root password.
echo "mysql-server mysql-server/root_password select pyflag" | debconf-set-selections 
echo "mysql-server mysql-server/root_password_again select pyflag" | debconf-set-selections 


# Downloading Ubuntu build tools and forensics tools dependencies.
echo "\n\nDownloading and installing build environment and program dependencies ...\n"
apt-get -y install build-essential automake autoconf libtool # Build environment packages.
apt-get -y install $LIBEWF_DEPS # Libewf dependencies.
apt-get -y install $AFFLIB_DEPS # Afflib dependencies.
apt-get -y install $PYFLAG_DEPS #pyflag dependencies
echo "\nBuild environment/dependencies installed!\n"


# Create forensics tools directory in "home/$USER".
if [ -d "$DL_DIR" ]
	then
		echo "Using $HOME/forensics/ to store and build programs.\n"
	else
		mkdir $DL_DIR
		echo "Creating $HOME/forensics/ directory to store and build programs.\n"
fi


# Install source code for forensics tools.
for i in $LIBEWF $AFFLIB $AIMAGE $TSK $PYFLAG; do
	cd $DL_DIR
	echo "\n\nDownloading $i...\n"
	if [ "$i" = "$LIBEWF" ]; then wget $LIBEWF_URL
	elif [ "$i" = "$AFFLIB" ]; then wget $AFFLIB_URL
	elif [ "$i" = "$AIMAGE" ]; then wget $AIMAGE_URL
	elif [ "$i" = "$TSK" ]; then wget $TSK_URL
	elif [ "$i" = "$PYFLAG" ]; then darcs get --partial $PYFLAG_URL
	fi
	echo "\n\nExpanding $i...\n"; tar xzvf $i.tar.gz
	cd $i
	if [ "$i" = "$PYFLAG" ]; then 
		echo "Preparing $i...\n"
		sh autogen.sh
	fi
	echo "\n\nConfiguring $i...\n"; ./configure
	echo "\n\nMaking $i...\n"; make
	echo "\n\nInstalling $i...\n"; make install
	echo "\n\nCleaning up...\n"; make clean
done


##### PyFLAG initialization

# Configure mysql for timezone support.
echo "\n\nConfiguring PyFLAG timezone support...\n"
mysql_tzinfo_to_sql /usr/share/zoneinfo/ | mysql -uroot --password=pyflag mysql

# Create pyflag configuration file
mkdir -p /usr/local/etc /tmp/{pyflag,pyflag/{upload,result}}

cat << EOF > /usr/local/etc/pyflagrc
[DEFAULT]

uploaddir=/tmp/pyflag/upload/ 
resultdir=/tmp/pyflag/result 
dbpasswd=pyflag 
EOF

chown -R $UID $DL_DIR/


exit 0

