#!/bin/bash
debug='>> /var/log/wazuh-installation.log 2>&1'
sys_type="yum"
rollback(){
 eval "docker container rm -f \$(docker container ls -aq)"
}
installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."
    if [ ${sys_type} == "yum" ]; then
        eval "yum install git curl unzip wget libcap epel-release jq -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        echo "Error: Prerequisites could not be installed"
        exit 1;
    else
        echo "Successfully installed Prerequisiters!!!"
    fi
}
installDocker(){
	eval "sysctl -w vm.max_map_count=262144"
	echo "vm.max_map_count=262144" >> /etc/sysctl.conf
	if [ -z $(which docker 2>/dev/null) ];then
		eval "curl -sSL https://get.docker.com/ | sh ${debug}"
	else
		echo "Docker is already installed!!!"
	fi
	if [  "$?" != 0  ]; then
	        echo "Error: Docker installation failed"
        	exit 1;
   	 else
		echo "Docker installed Successfully!!!"
	fi
	if [ -z $(which docker-compose 2>/dev/null) ];then
		eval "curl -L \"https://github.com/docker/compose/releases/download/1.28.3/docker-compose-$(uname -s)-$(uname -m)\" -o /usr/local/bin/docker-compose ${debug}"
		eval "chmod +x /usr/local/bin/docker-compose ${debug}"
	else
		echo "Docker compose is already installed!!!"
	fi
	if [  "$?" != 0  ]; then
                echo "Error: Docker-compose installation failed"
                exit 1;
         else
                echo "Docker-compose installed Successfully!!!"
        fi
}
checkArch() {
    arch=$(uname -m)
    if [ ${arch} != "x86_64" ]; then
        echo "Uncompatible system. This script must be run on a 64-bit system."
        exit 1;
    fi
}
upAndRunDocker(){
startService "docker"
	eval "cd /opt && git clone https://github.com/wazuh/wazuh-docker.git -b v4.1.5 --depth=1 ${debug}"
	eval "chcon -R system_u:object_r:admin_home_t:s0 /opt/wazuh-docker ${debug}"
	eval "docker-compose -f /opt/wazuh-docker/generate-opendistro-certs.yml run --rm generator ${debug}"
	eval "bash /opt/wazuh-docker/production_cluster/kibana_ssl/generate-self-signed-cert.sh ${debug}"
	eval "bash /opt/wazuh-docker/production_cluster/nginx/ssl/generate-self-signed-cert.sh ${debug}"
	eval "docker-compose -f /opt/wazuh-docker/production-cluster.yml up -d ${debug}"
	if [  "$?" != 0  ]; then
                echo "Error: wazuh-docker production cluster installation failed"
		echo "Wait...i am trying to up and down it once more"
		startService "docker"
		rollback 
                exit 1;
         else
                echo "docker images created Successfully!!!"
        fi
}
installFileBeat(){
	if [ -z $(which filebeat 2>/dev/null) ];then
		eval "cd /opt && curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-7.8.1-x86_64.rpm"
		eval "sudo rpm -vi filebeat-oss-7.8.1-x86_64.rpm ${debug}"
	else
		echo "filebeat already installed with version $(filebeat version)"
	fi
	if [  "$?" != 0  ]; then
                echo "Error: Filebeat installation failed"
                exit 1;
         else
                echo "filebeat installed Successfully!!!"
        fi
startService "filebeat"
}
installAuditBeat(){
	if [ -z $(which auditbeat 2>/dev/null) ];then
		eval "cd /opt && curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-oss-7.8.1-x86_64.rpm"
		eval "sudo rpm -vi auditbeat-oss-7.8.1-x86_64.rpm ${debug}"
	else
		echo "auditbeat already installed with version $(auditbeat version)"
	fi
	if [  "$?" != 0  ]; then
                echo "Error: Auditbeat installation failed"
                exit 1;
         else
                echo "Auditbeat installed Successfully!!!"
        fi
startService "auditbeat"
}
installWazuhAgent(){
	eval "rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH ${debug}"
	eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo ${debug}"
	eval "yum install wazuh-agent -y ${debug}"
	if [  "$?" != 0  ]; then
                echo "Error: WazuhAgent installation failed"
                exit 1;
         else
                echo "Wazuh-Agent installed Successfully!!!"
        fi
startService "wazuh-agent"
}
installSuricata(){
	if [ -z $(which suricata 2>/dev/null) ];then
		eval "cd /opt ${debug}"
		eval "curl -O https://copr.fedorainfracloud.org/coprs/jasonish/suricata-stable/repo/epel-7/jasonish-suricata-stable-epel-7.repo --max-time 300 ${debug}"
		eval "yum -y install suricata ${debug}"
	else
		echo "suricata is already installed with version $(suricata -V)"
	fi
	if [  "$?" != 0  ]; then
                echo "Error: Suricata installation failed"
                exit 1;
         else
                echo "Suricata installed Successfully!!!"
        fi
	if [ -e $emerging.rules.tar.gz ];then
		echo "Suricata Rules File Already Exists"
	else
		eval "wget https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz ${debug}"
	fi
	eval "tar zxvf emerging.rules.tar.gz ${debug}"
	eval "rm /etc/suricata/rules/* -f ${debug}"
	eval "mv rules/*.rules /etc/suricata/rules/ ${debug}"
	eval "rm -f /etc/suricata/suricata.yaml ${debug}"
	eval "wget -O /etc/suricata/suricata.yaml http://www.branchnetconsulting.com/wazuh/suricata.yaml ${debug}"
#startService "suricata"
}
startService(){
	eval "systemctl daemon-reload ${debug}"
	eval "systemctl enable $1.service ${debug}"
	eval "systemctl start $1.service ${debug}"
	if [  "$?" != 0  ]; then
            echo "${1^} could not be started."
	    exit 1;
	else
	    echo "${1^} started"
	fi
}
main() {
if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1;
fi
installPrerequisites
installDocker
upAndRunDocker
installFileBeat
installAuditBeat
installWazuhAgent
installSuricata
#rollback
}
main "$@"
