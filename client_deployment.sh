#!/bin/bash
debug='>> /var/log/wazuh-installation.log 2>&1'
sys_type="yum"
baseFolder="/opt/SIEM/"
modifyFilePath="/tmp/file1/modify_files/"
#ip=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
ip=172.25.2.50
hostname=
installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."
    if [ ${sys_type} == "yum" ]; then
        eval "cd ${baseFolder}"
        eval "wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm ${debug}"
        eval "yum install ./epel-release-latest-*.noarch.rpm -y ${debug}"
        eval "yum clean all"
        eval "yum install epel-release git curl unzip wget libpcap-devel python3 -y ${debug}"
        eval "pip3  install -r /tmp/file1/requirements.txt"
    fi
    if [  "$?" != 0  ]; then
        echo "Error: Prerequisites could not be installed"
        exit 1;
    else
        echo "Successfully installed Prerequisiters!!!"
    fi
}
copyCertificateFromServer(){
        eval "mkdir -p ${baseFolder}/elasticsearch_certs && mkdir -p ${baseFolder}/kibana_certs ${debug}"
        #eval "scp -P 42111 ${ip}:/${baseFolder}/elasticsearch_certs/* ${baseFolder}/elasticsearch_certs ${debug}"
        #eval "scp -P 42111 ${ip}:/${baseFolder}/kibana_certs/* ${baseFolder}/kibana_certs ${debug}"
}
installFileBeat(){
        if [ -z $(which filebeat 2>/dev/null) ];then
                eval "cd ${baseFolder} && curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-7.8.1-x86_64.rpm ${debug}"
                eval "sudo rpm -vi filebeat-oss-7.8.1-x86_64.rpm ${debug}"
                eval "cp ${modifyFilePath}/filebeat.yml /etc/filebeat/filebeat.yml ${debug}"
                sed -i "s/172.26.0.38:9201/${ip}:9201/g" /etc/filebeat/filebeat.yml
                sed -i "s/https:\/\/172.26.0.38:4443/https:\/\/${ip}:4343/g" /etc/filebeat/filebeat.yml
                eval "filebeat modules enable system ${debug}"
                eval "mkdir -p /etc/filebeat/certs ${debug}"
                eval "cp ${baseFolder}/elasticsearch_certs/{node1.key,node1.pem,root-ca.pem} /etc/filebeat/certs/ ${debug}"
                eval "cp ${baseFolder}/kibana_certs/{cert.pem,key.pem} /etc/filebeat/certs/ ${debug}"
                eval "cp ${modifyFilePath}/system.yml /etc/filebeat/modules.d/system.yml ${debug}"
        else
                echo "filebeat already installed with version $(filebeat version)"
                eval "yum remove filebeat -y"
                installFileBeat
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
                eval "cd ${baseFolder} && curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-oss-7.8.1-x86_64.rpm ${debug}"
                eval "sudo rpm -vi auditbeat-oss-7.8.1-x86_64.rpm ${debug}"
		eval "service auditd stop"
                eval "sleep 5"
                eval "cp ${modifyFilePath}/auditbeat.yml /etc/auditbeat/auditbeat.yml ${debug}"
                sed -i "s/172.26.0.38:9201/${ip}:9201/g" /etc/auditbeat/auditbeat.yml
                sed -i "s/https:\/\/172.26.0.38:4443/https:\/\/${ip}:4343/g" /etc/auditbeat/auditbeat.yml
                eval "mkdir -p /etc/auditbeat/certs ${debug}"
                eval "cp ${baseFolder}/elasticsearch_certs/{node1.key,node1.pem,root-ca.pem} /etc/auditbeat/certs/ ${debug}"
                eval "cp ${baseFolder}/kibana_certs/{cert.pem,key.pem} /etc/auditbeat/certs/ ${debug}"
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
        eval "cp ${modifyFilePath}/ossec.conf /var/ossec/etc/ossec.conf ${debug}"
        sed -i "s/MANAGER_IP/${ip}/" /var/ossec/etc/ossec.conf
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
                eval "cd ${baseFolder} ${debug}"
                eval "curl -O https://copr.fedorainfracloud.org/coprs/jasonish/suricata-stable/repo/epel-7/jasonish-suricata-stable-epel-7.repo --max-time 300 ${debug}"
                eval "yum -y install suricata ${debug}"
                eval "tar zxvf emerging.rules.tar.gz ${debug}"
                eval "rm /etc/suricata/rules/* -f ${debug}"
                eval "mv rules/*.rules /etc/suricata/rules/ ${debug}"
                eval "rm -f /etc/suricata/suricata.yaml ${debug}"
                eval "wget -O /etc/suricata/suricata.yaml http://www.branchnetconsulting.com/wazuh/suricata.yaml ${debug}"
                eval "yes|cp ${modifyFilePath}/suricata.yaml /etc/suricata/suricata.yaml"
                eval "yes|cp ${modifyFilePath}/custom.rules /etc/suricata/rules/ ${debug}"
                ip=$(ip a|grep -w inet|sed -n '2,$p'|awk '{print $2}'|sed 's/^\|$//g'|paste -sd, -)
                sed -i 's|network_range|'"${ip}"'|g' /etc/suricata/suricata.yaml
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
startService "suricata"
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
customYumLog(){
        eval "cp -vr ${modifyFilePath}/final_yum_parser_python.py ${baseFolder} ${debug}"
        echo "127.0.0.1 ${hostname} elasticsearch">>/etc/hosts
	eval "cat <(crontab -l) <(echo '0 * * * * python3 /opt/SIEM/final_yum_parser_python.py') | crontab -"
        eval "python3 /opt/SIEM/final_yum_parser_python.py ${debug}"
}
main() {
if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1;
fi
mkdir -p ${baseFolder}
installPrerequisites
copyCertificateFromServer
installFileBeat
installAuditBeat
installWazuhAgent
installSuricata
customYumLog
}
main "$@"
