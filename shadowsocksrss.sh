#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#===============================================================================================
#   System Required:  CentOS6.x (32bit/64bit)
#   Description: Install ShadowsocksRSS server for CentOS 6 or 7
#   Author: Teddysun <i@teddysun.com>
#   Thanks: @m0d8ye <https://twitter.com/m0d8ye>
#   Intro:  http://teddysun.com/357.html
#===============================================================================================

clear
echo "#############################################################"
echo "# Install ShadowsocksRSS server for CentOS 6 or 7        #"
echo "# Intro: http://teddysun.com/357.html                       #"
echo "# Author: Teddysun <i@teddysun.com>                         #"
echo "# Thanks: @m0d8ye <https://twitter.com/m0d8ye>              #"
echo "#############################################################"
echo ""

# Make sure only root can run our script
function rootness(){
if [[ $EUID -ne 0 ]]; then
   echo "Error:This script must be run as root!" 1>&2
   exit 1
fi
}

# Get version
function getversion(){
    if [[ -s /etc/redhat-release ]];then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else    
        grep -oE  "[0-9.]+" /etc/issue
    fi    
}

# CentOS version
function centosversion(){
    local code=$1
    local version="`getversion`"
    local main_ver=${version%%.*}
    if [ $main_ver == $code ];then
        return 0
    else
        return 1
    fi        
}

# Disable selinux
function disable_selinux(){
if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
fi
}

# Pre-installation settings
function pre_install(){
    # Not support CentOS 5
    if centosversion 5; then
        echo "Not support CentOS 5, please change to CentOS 6 or 7 and try again."
        exit 1
    fi
    #disable yum update kernel
 #   sed -i '/plugins=1/i\exclude=kernel*' /etc/yum.conf
   
    # install epel repo for centos 6
    if centosversion 6; then
        echo ""
        echo "install epel repo for centos 6."
        echo ""
        yum install -y wget git
        if [ $( ls /etc/yum.repos.d/ | grep epel |wc -l ) -eq 0 ]; then
          rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm && rpm --import http://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-6
        else
           echo "Epel repo has been installed."
        fi
    fi

    # install and enable iptables for centos 7
    if centosversion 7; then
        echo ""
        echo "Disable the firewalld, install iptables and make it enable with startup."
        echo ""
        yum install -y wget git
        if [ $( ls /etc/yum.repos.d/ | grep epel |wc -l ) -eq 0 ]; then
          rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && rpm --import http://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7
          rpm -ivh http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.3-1.el7.rf.x86_64.rpm
          rpm -ivh http://rpms.famillecollet.com/enterprise/remi-release-7.rpm && rpm --import http://rpms.famillecollet.com/RPM-GPG-KEY-remi
        else
           echo "Epel repo has been installed."
        fi
        yum install -y iptables-services
        systemctl disable firewalld.service
        systemctl stop firewalld.service
        systemctl restart iptables.service
        systemctl enable iptables.service
    fi
    #Set ShadowsocksRSS config password
    echo ""
    echo "Please input password for ShadowsocksRSS:"
    read -p "(Default password: Aa-11111):" shadowsockspwd
    [ -z "$shadowsockspwd" ] && shadowsockspwd="Aa-11111"
    echo ""
    echo "---------------------------"
    echo "password = $shadowsockspwd"
    echo "---------------------------"
    echo ""
	#Set shadowsocksRSS config protocol
    echo ""
    echo "Please input protocol for shadowsocksRSS("origin" & "verify_simple" & "verify_deflate" & "auth_simple"):"
    read -p "(Default protocol: verify_sha1_compatible):" shadowsocksprotocol
    [ -z "$shadowsocksprotocol" ] && shadowsocksprotocol="verify_sha1_compatible"
    echo ""
    echo "---------------------------"
    echo "protocol = $shadowsocksprotocol"
    echo "---------------------------"
    echo ""
	    #Set shadowsocksRSS config obfs
    echo ""
    echo "Please input obfs for shadowsocksRSS("plain" & "http_simple" & "tls_simple" & "tls_simple_compatible" & "random_head" & "random_head_compatible"):"
    read -p "(Default obfs: http_simple_compatible):" shadowsocksobfs
    [ -z "$shadowsocksobfs" ] && shadowsocksobfs="http_simple_compatible"
    echo ""
    echo "---------------------------"
    echo "obfs = $shadowsocksobfs"
    echo "---------------------------"
    echo ""
    #Set ShadowsocksRSS config method
    echo ""
    echo "Please input method for shadowsocksRSS("rc4-md5" and "chacha20" are suggested.):"
    read -p "(Default method: aes-256-cfb):" shadowsocksmethod
    [ -z "$shadowsocksmethod" ] && shadowsocksmethod="aes-256-cfb"
    echo ""
    echo "---------------------------"
    echo "method = $shadowsocksmethod"
    echo "---------------------------"
    echo ""
    #Set ShadowsocksRSS config port
    while true
    do
    echo -e "Please input port for ShadowsocksRSS [1-65535]:"
    read -p "(Default port: 443):" shadowsocksport
    [ -z "$shadowsocksport" ] && shadowsocksport="443"
    expr $shadowsocksport + 0 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ $shadowsocksport -ge 1 ] && [ $shadowsocksport -le 65535 ]; then
            echo ""
            echo "---------------------------"
            echo "port = $shadowsocksport"
            echo "---------------------------"
            echo ""
            break
        else
            echo "Input error! Please input correct numbers."
        fi
    else
        echo "Input error! Please input correct numbers."
    fi
    done
    get_char(){
        SAVEDSTTY=`stty -g`
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty $SAVEDSTTY
    }
    echo ""
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`
    #Install necessary dependencies
    echo ""
    echo "----------------------------"
    echo "Install necessary dependencies:"
    echo "----------------------------"
    echo ""
    yum clean all && yum update -y
    yum install -y wget libffi libffi-devel net-tools libsodium m2crypto python-cffi
    yum install -y texinfo gcc unzip vim libidn
    yum install -y  openssl-devel swig autoconf libtool libevent
    yum install -y python python-devel python-setuptools git
    yum install -y automake make curl curl-devel zlib zlib-devel
    yum install -y perl perl-devel cpio expat-devel gettext-devel bc
    if ! wget --no-check-certificate -O ez_setup.py https://bootstrap.pypa.io/ez_setup.py; then
         echo "Failed to download ez_setup.py!"
         exit 1
    fi
    python ez_setup.py install
    easy_install pip
    pip install pyopenssl ndg-httpsclient pyasn1
    pip install greenlet
    pip install gevent
    service network restart
    # Get IP address
    echo "Getting Public IP address, Please wait a moment..."
    IP=$(curl -s -4 icanhazip.com)
    if [[ "$IP" = "" ]]; then
        IP=`curl -s -4 ipinfo.io | grep "ip" | awk -F\" '{print $4}'`
    fi
    echo -e "Your main public IP is\t\033[32m$IP\033[0m"
    echo ""
    #Current folder
    cur_dir=`pwd`
    cd $cur_dir
}

# Download latest ShadowsocksRSS
function download_files(){
    if [ -f shadowsocks ];then
        echo "shadowsocks folder [found]"
    else
        git clone -b manyuser https://github.com/breakwa11/shadowsocks.git		
        cd $cur_dir/shadowsocks/shadowsocks/
    fi
    # Download start script
    if ! wget --no-check-certificate monokoo.com/script/rss/shadowsocksr; then
        echo "Failed to download shadowsocksRss start script!"
        exit 1
    fi
}

# Config shadowsocks
function config_shadowsocks(){
    if [ ! -d /etc/shadowsocksrss ];then
        mkdir /etc/shadowsocksrss
    fi
    cat > /etc/shadowsocksrss/config.json<<-EOF
{
    "server":"0.0.0.0",
    "local_address":"127.0.0.1",
    "local_port":1080,
    "port_password":{
        "${shadowsocksport}":{"protocol":"${shadowsocksprotocol}", "password":"${shadowsockspwd}", "obfs":"${shadowsocksobfs}", "obfs_param":""},
        "21472":{"protocol":"auth_sha1", "password":"Aa-11111", "obfs":"http_simple", "obfs_param":""},
        "3389":{"protocol":"auth_simple", "password":"HuangChen", "obfs":"http_simple", "obfs_param":""},
        "3390":{"protocol":"${shadowsocksprotocol}", "password":"HuangChen", "obfs":"${shadowsocksobfs}", "obfs_param":""},
        "4545":{"protocol":"origin", "password":"hwy1415", "obfs":"http_simple_compatible", "obfs_param":""},
        "4550":{"protocol":"${shadowsocksprotocol}", "password":"Yourej", "obfs":"${shadowsocksobfs}", "obfs_param":""},
        "35205":{"protocol":"auth_simple", "password":"123Abc", "obfs":"http_simple", "obfs_param":""},
        "43389":{"protocol":"verify_sha1", "password":"HuangXchen", "obfs":"tls1.0_session_auth", "obfs_param":""}
    },
    "timeout":190,
    "method":"${shadowsocksmethod}",
    "protocol": "auth_sha1_compatible",
    "protocol_param": "",
    "obfs": "tls1.0_session_auth_compatible",
    "obfs_param": "",
    "redirect": "",
    "fast_open":false,
    "workers":1
}
EOF

}

# iptables set
function iptables_set(){
    echo "iptables start setting..."
    service iptables status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        if [  $(iptables -nL| grep dpt:${shadowsocksport} | grep ACCEPT |wc -l) -eq 0 ]; then
           sed -i '/*filter/{n;s/:INPUT ACCEPT/:INPUT DROP/g}' /etc/sysconfig/iptables
           sed -i '/-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT/i\-A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j DROP' /etc/sysconfig/iptables
           sed -i '/-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT/i\-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP' /etc/sysconfig/iptables
           sed -i '/-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT/i\-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP' /etc/sysconfig/iptables
#          sed -i '/-A INPUT -i lo -j ACCEPT/a\-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 1/sec -j ACCEPT' /etc/sysconfig/iptables
           sed -i '/-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT/i\-A INPUT -m state --state INVALID -j DROP' /etc/sysconfig/iptables
           sed -i 's/-A INPUT -p icmp -j ACCEPT/-A INPUT -p icmp --icmp-type 8 -j ACCEPT/' /etc/sysconfig/iptables
           sed -i '/-A FORWARD -j REJECT --reject-with icmp-host-prohibited/i\-A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK RST -m limit --limit 1/sec -j ACCEPT' /etc/sysconfig/iptables
           sed -i '/-A FORWARD -j REJECT --reject-with icmp-host-prohibited/i\-A FORWARD -p icmp -m icmp --icmp-type 8 -m limit --limit 1/sec -j ACCEPT' /etc/sysconfig/iptables
           sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -m state --state NEW -m tcp -p tcp --dport '$shadowsocksport' -j ACCEPT' /etc/sysconfig/iptables

           sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -p tcp -m multiport --dport 21472,3389,3390,4545,4550,35205,43389 -j ACCEPT' /etc/sysconfig/iptables
#          sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -m state --state NEW -m tcp -p tcp --dport 21472 -j ACCEPT' /etc/sysconfig/iptables
#          sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -m state --state NEW -m tcp -p tcp --dport 3389 -j ACCEPT' /etc/sysconfig/iptables
#          sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -m state --state NEW -m tcp -p tcp --dport 3390 -j ACCEPT' /etc/sysconfig/iptables
#          sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -m state --state NEW -m tcp -p tcp --dport 4545 -j ACCEPT' /etc/sysconfig/iptables
#          sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -m state --state NEW -m tcp -p tcp --dport 4550 -j ACCEPT' /etc/sysconfig/iptables
#          sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -m state --state NEW -m tcp -p tcp --dport 35205 -j ACCEPT' /etc/sysconfig/iptables
#          sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/d' /etc/sysconfig/iptables
           service iptables restart
        else
            echo ""
            iptables -nL| grep --dport | grep ACCEPT
            echo ""
            echo "port ${shadowsocksport} has been set up."
        fi
    else
        echo "iptables looks like shutdown, please manually set it if necessary."
    fi
}

# Install 
function install(){
    # Build and Install ShadowsocksRSS
    if [ -s /etc/shadowsocksrss ];then
        if [ $? -eq 0 ]; then
            mv $cur_dir/shadowsocks/shadowsocks/shadowsocksr /etc/init.d/shadowsocksr
			rm -f shadowsocksr
			mv $cur_dir/shadowsocks/ /opt/shadowsocksrss
            chmod +x /etc/init.d/shadowsocksr
            # Add run on system start up
            chkconfig --add shadowsocksr
            chkconfig shadowsocksr on
            # Start shadowsocks
            service shadowsocksr start
            if [ $? -eq 0 ]; then
                echo "ShadowsocksRSS start success!"
            else
                echo "ShadowsocksRSS start failure!"
            fi
        else
            echo ""
            echo "ShadowsocksRSS install failed!"
            exit 1
        fi
    fi
    #configure the environment profile for shortcut keys
    wget http://monokoo.com/script/env
    cat env>>/etc/profile
    source /etc/profile
    rm -rf env

    #configure the new libsodium
    wget https://github.com/jedisct1/libsodium/releases/download/1.0.8/libsodium-1.0.8.tar.gz
    tar xf libsodium-1.0.8.tar.gz && cd libsodium-1.0.8
    ./configure && make -j2 && make install
    ldconfig
    cd ../ && rm -rf libsodium-1.0.8
}

function install_serverspeeder(){
    # Install the serverspeeder for your vps
  echo ""
  echo "........................"
  if [ -s /serverspeeder/bin/serverSpeeder.sh ];then
    echo "ServerSpeeder has been installed!"
#   exit 1
  else
    kernel=$(uname -r|grep stab|wc -l)
    kernelver=$(uname -r)
    echo -e "Your VPS's kernel is: \033[41;37m ${kernelver} \033[0m"
    if [ $kernel -eq 0 ]; then
       echo ""
       echo " \033[41;37m Install the ServerSpeeder for your VPS: \033[0m"
       echo ""
       wget http://my.serverspeeder.com/d/ls/serverSpeederInstaller.tar.gz
       tar zxvf serverSpeederInstaller.tar.gz
       bash serverSpeederInstaller.sh
       echo "Change the configuration of the ServerSpeeder for your VPS:..."
       sed -i 's/advinacc="0"/advinacc="1"/g' "/serverspeeder/etc/config"
       sed -i 's/maxmode="0"/maxmode="1"/g' "/serverspeeder/etc/config"
       sed -i 's/rsc="0"/rsc="1"/g' "/serverspeeder/etc/config"
       sed -i 's/gso="0"/gso="1"/g' "/serverspeeder/etc/config"
       sed -i 's/accppp="0"/accppp="1"/g' "/serverspeeder/etc/config"
       /sbin/modprobe tcp_hybla
       cat > /etc/sysctl.conf<<-EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.core.rmem_max = 12582912
net.core.wmem_max = 12582912
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
net.core.netdev_max_backlog = 250000
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = hybla
net.ipv4.tcp_fastopen = 3
EOF
       sysctl -p
       echo "Restart the ServerSpeeder for your VPS:..."
       /serverspeeder/bin/serverSpeeder.sh restart
       if [ $(ps -ef|grep serverSpeeder|wc -l) -eq 0 ]; then
          echo "Installation for serverspeeder has failed, please manually install it."
       else
          echo ""
          echo "ServerSpeeder has been successfully installed on your VPS."
          echo ""
          rm -rf serverSpeederInstaller*
       fi
    else
       echo "Your VPS is not able to install the serverspeeder."
#      exit 0
    fi
  fi
}

function print_info(){
    #print the result of installation
    echo "........................"
    echo ""
    cd $cur_dir
    # Delete ShadowsocksRSS floder
    rm -rf ez_setup.py setuptools-19.2.zip
    clear
    echo ""
    echo "Congratulations, ShadowsocksRSS install completed!"
    echo -e "Your Server IP: \033[41;37m ${IP} \033[0m"
    echo -e "Your Server Port: \033[41;37m ${shadowsocksport} \033[0m"
    echo -e "Your Password: \033[41;37m ${shadowsockspwd} \033[0m"
#   echo -e "Your Second Server Port: \033[41;37m 3389 \033[0m"
#   echo -e "Your Second Password: \033[41;37m HuangChen \033[0m"
    echo -e "Your Protocol: \033[41;37m ${shadowsocksprotocol} \033[0m"
    echo -e "Your Obfs: \033[41;37m ${shadowsocksobfs} \033[0m"
    echo -e "Your Local IP: \033[41;37m 127.0.0.1 \033[0m"
    echo -e "Your Local Port: \033[41;37m 1080 \033[0m"
    echo -e "Your Encryption Method: \033[41;37m ${shadowsocksmethod} \033[0m"
    echo ""
    echo "Welcome to visit:http://teddysun.com/357.html"
    echo "Enjoy it!"
    echo ""
    exit 0
}


# Install shadowsocksRSS
function install_shadowsocks_rss(){
    rootness
    disable_selinux
    pre_install
    download_files
    config_shadowsocks
    iptables_set
    install
    install_serverspeeder
    print_info
}

# Initialization step
action=$1
[  -z $1 ] && action=install
case "$action" in
install)
    install_shadowsocks_rss
    ;;
*)
    echo "Arguments error! [${action} ]"
    echo "Usage: `basename $0` {install|uninstall}"
    ;;
esac
