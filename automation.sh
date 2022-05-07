#!/bin/bash
debug='>> /var/log/wazuh-installation.log 2>&1'
sys_type="yum"
baseFolder="/opt/SIEM/"
modifyFilePath="/tmp/file1/modify_files/"
ip=172.17.78.79


rollback(){
 eval "docker container rm -f \$(docker container ls -aq)"
}

installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."
    if [ ${sys_type} == "yum" ]; then
        eval "wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm ${debug}"
	eval "yum clean all"
        eval "yum install ./epel-release-latest-*.noarch.rpm -y ${debug}"
        eval "yum install epel-release git curl unzip wget libpcap-devel python3 -y ${debug}"
        eval "pip3 install -r /tmp/file1/requirements.txt ${debug}"
    fi
    if [  "$?" != 0  ]; then
        echo "Error: Prerequisites could not be installed"
        exit 1;
    else
        echo "Successfully installed Prerequisiters!!!"
    fi
}

installDocker(){
        eval "sysctl -w vm.max_map_count=262144 ${debug}"
        variable=$(sed -n '$p' /etc/sysctl.conf)
        if [ $variable == "sysctl -w vm.max_map_count=262144" ]; then
                echo "vm.max_map_count=262144" >> /etc/sysctl.conf
        fi
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
#startService "docker"
	eval "yes|cp -vr ${modifyFilePath}/daemon.json /etc/docker/daemon.json"
        #startService "docker"
	eval "systemctl restart docker ${debug}"
	   #eval "mkdir -p /opt/SIEM ${debug}"
        eval "cd ${baseFolder} ${debug}"
        if [ ! -d "${baseFolder}/wazuh-docker" ]; then
                eval "git clone https://github.com/wazuh/wazuh-docker.git -b v4.1.5 --depth=1 ${debug}"
		eval "cd /opt/SIEM/wazuh-docker" 
		# sed -ie "s/3.7/2.3/g" production-cluster.yml
        else
                eval "rm -rf ${baseFolder}/wazuh-docker ${debug}"
                eval "sleep 10"
                echo "wazuh-docker delete successfully ${debug}"
                eval "sleep 10"
                upAndRunDocker
        fi

	eval "yes|cp ${modifyFilePath}/production-cluster.yml ${baseFolder}/wazuh-docker"
        eval "chcon -R system_u:object_r:admin_home_t:s0 ${baseFolder}/wazuh-docker ${debug}"
        #sed -i 's/9200:9200/9201:9200/g;s/5601:5601/5602:5601/g;s/80:80/8083:80/g;s/443:443/4343:443/g;s/ES_JAVA_OPTS=-Xms512m -Xmx512m/ES_JAVA_OPTS=-Xms1g -Xmx1g/g' ${baseFolder}/wazuh-docker/production-cluster.yml
	#sed -i 's/elastic-data-1/\/apollo\/backup\/wazuh-data\/elastic-data-1/g;s/elastic-data-2/\/apollo\/backup\/wazuh-data\/elastic-data-2/;s/elastic-data-3/\/apollo\/backup\/wazuh-data\/elastic-data-3/' ${baseFolder}/wazuh-docker/production-cluster.yml
        eval "docker-compose -f ${baseFolder}/wazuh-docker/generate-opendistro-certs.yml run --rm generator ${debug}"
	eval "for p in $(docker network ls |grep wazuh-docker_default |awk '{ print $1 }') ; do ip link set br-$p promisc on ; done ${debug}"
        eval "bash ${baseFolder}/wazuh-docker/production_cluster/kibana_ssl/generate-self-signed-cert.sh ${debug}"
        eval "bash ${baseFolder}/wazuh-docker/production_cluster/nginx/ssl/generate-self-signed-cert.sh ${debug}"
        eval "docker-compose -f ${baseFolder}/wazuh-docker/production-cluster.yml up -d ${debug}"
	sleep 5
        eval "docker-compose -f ${baseFolder}/wazuh-docker/production-cluster.yml down ${debug}"
	eval "docker network rm  wazuh-docker_default ${debug}"
        eval "docker-compose -f ${baseFolder}/wazuh-docker/production-cluster.yml up -d ${debug}"
        if [  "$?" != 0  ]; then
                echo "Error: wazuh-docker production cluster installation failed"
                echo "Wait...i am trying to up and down it once more"
                startService "docker"
                rollback
                upAndRunDocker
                exit 1;
         else
                echo "docker images created Successfully!!!"
        fi
}

copyCertificateFromDcoker(){
        eval "mkdir -p ${baseFolder}/elasticsearch_certs && mkdir -p ${baseFolder}/kibana_certs ${debug}"
        eval "docker exec wazuhdocker_elasticsearch_1 bash -c 'cd /usr/share/elasticsearch/config/ ; tar -czvf /tmp/elasticsearch_certs.tar.gz node1.key node1.pem root-ca.pem'"
        if [ "$?" != 0 ]; then
                eval "docker exec wazuh-docker_elasticsearch_1 bash -c 'cd /usr/share/elasticsearch/config/ ; tar -czvf /tmp/elasticsearch_certs.tar.gz node1.key node1.pem root-ca.pem'"
        fi
        sleep 2
        eval "docker exec wazuhdocker_kibana_1 bash -c 'cd /usr/share/kibana/config; tar -czvf /tmp/kibana_certs.tar.gz cert.pem key.pem'"
        if [ "$?" != 0 ]; then
                eval "docker exec wazuh-docker_kibana_1 bash -c 'cd /usr/share/kibana/config; tar -czvf /tmp/kibana_certs.tar.gz cert.pem key.pem'"
        fi
        sleep 2
        eval "docker cp wazuhdocker_elasticsearch_1:/tmp/elasticsearch_certs.tar.gz /opt/SIEM/elasticsearch_certs/"
        if [ "$?" != 0 ];then
                eval "docker cp wazuh-docker_elasticsearch_1:/tmp/elasticsearch_certs.tar.gz /opt/SIEM/elasticsearch_certs/"
        fi
        eval "docker cp wazuhdocker_kibana_1:/tmp/kibana_certs.tar.gz /opt/SIEM/kibana_certs/"
        if [ "$?" != 0 ];then
                eval "docker cp wazuh-docker_kibana_1:/tmp/kibana_certs.tar.gz /opt/SIEM/kibana_certs/"
        fi
        eval "tar -xzvf /opt/SIEM/elasticsearch_certs/elasticsearch_certs.tar.gz -C /opt/SIEM/elasticsearch_certs/"
        eval "tar -xzvf /opt/SIEM/kibana_certs/kibana_certs.tar.gz -C /opt/SIEM/kibana_certs/"
        eval "cd ${baseFolder} ; tar -czvf ssl-SIEM-certs.tar.gz elasticsearch_certs/ kibana_certs/ ${debug}"
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
                #eval "cp ${baseFolder}/elasticsearch_certs/{node1.key,node1.pem,root-ca.pem} /etc/filebeat/certs/ ${debug}"
                #eval "cp ${baseFolder}/kibana_certs/{cert.pem,key.pem} /etc/filebeat/certs/ ${debug}"
                #eval "cp ${modifyFilePath}/system.yml /etc/filebeat/modules.d/system.yml ${debug}"
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
		eval "service stop auditd ${debug}"
		eval "systemctl disable auditd ${debug}"
                eval "cd ${baseFolder} && curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-oss-7.8.1-x86_64.rpm ${debug}"
                eval "sudo rpm -vi auditbeat-oss-7.8.1-x86_64.rpm ${debug}"
                eval "sleep 5"
                eval "cp ${modifyFilePath}/auditbeat.yml /etc/auditbeat/auditbeat.yml ${debug}"
                sed -i "s/172.26.0.38:9201/${ip}:9201/g" /etc/auditbeat/auditbeat.yml
                sed -i "s/https:\/\/172.26.0.38:4443/https:\/\/${ip}:4343/g" /etc/auditbeat/auditbeat.yml
                eval "mkdir -p /etc/auditbeat/certs ${debug}"
                #eval "cp ${baseFolder}/elasticsearch_certs/{node1.key,node1.pem,root-ca.pem} /etc/auditbeat/certs/ ${debug}"
                #eval "cp ${baseFolder}/kibana_certs/{cert.pem,key.pem} /etc/auditbeat/certs/ ${debug}"
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
		eval "wget https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz ${debug}"
                eval "tar zxvf emerging.rules.tar.gz ${debug}"
                eval "rm /etc/suricata/rules/* -f ${debug}"
                eval "mv rules/*.rules /etc/suricata/rules/ ${debug}"
                eval "rm -f /etc/suricata/suricata.yaml ${debug}"
                eval "wget -O /etc/suricata/suricata.yaml http://www.branchnetconsulting.com/wazuh/suricata.yaml ${debug}"
                eval "yes|cp ${modifyFilePath}/suricata.yaml /etc/suricata/suricata.yaml"
                eval "yes|cp ${modifyFilePath}/custom.rules /etc/suricata/rules/ ${debug}"
                #ip=$(ip a|grep -w inet|sed -n '2,$p'|awk '{print $2}'|sed 's/^\|$//g'|paste -sd, -)
		#add home network and dvc range
		for p in $(ip a|grep -w inet|sed -n '2,$p'|awk '{print $2}'|sed 's/^\|$//g'|paste -sd, -) ;do sed -i 's|network_range|'"10.121.0.0/16,${p}"'|g' /etc/suricata/suricata.yaml ; done
                sed -i 's/EXTERNAL_NET: \"any\"/EXTERNAL_NET: "!$HOME_NET"/' /etc/suricata/suricata.yaml
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


importDashboard(){
#	sleep 120
        curl -X POST "https://${ip}:5602/api/saved_objects/_import?createNewCopies=true" --form file=@/tmp/file1/modify_files/dashboard/yum-custom-dashboard.ndjson -H 'kbn-xsrf: true' -k -u admin:SecretPassword --max-time 300 >> /var/log/wazuh-installation.log 2>&1
#	sleep 10
        curl -X POST "https://${ip}:5602/api/saved_objects/_import?createNewCopies=true" --form file=@/tmp/file1/modify_files/dashboard/NIDS.ndjson -H 'kbn-xsrf: true' -k -u admin:SecretPassword  --max-time 300 >> /var/log/wazuh-installation.log 2>&1
#	sleep 10
        curl -X POST "https://${ip}:5602/api/saved_objects/_import?createNewCopies=true" --form file=@/tmp/file1/modify_files/dashboard/Command-Execution-by-Users.ndjson -H 'kbn-xsrf: true' -k -u admin:SecretPassword  --max-time 300 >> /var/log/wazuh-installation.log 2>&1
#	sleep 10
        curl -X POST "https://${ip}:5602/api/saved_objects/_import?createNewCopies=true" --form file=@/tmp/file1/modify_files/dashboard/User-Login_attempts.ndjson -H 'kbn-xsrf: true' -k -u admin:SecretPassword  --max-time 300 >> /var/log/wazuh-installation.log 2>&1
}

customYumLog(){
	eval "for p in $(docker network ls |grep wazuh-docker_default |awk '{ print $1 }') ; do ip link set br-$p promisc on ; done ${debug}"
	eval "/usr/sbin/ip link set $(/usr/sbin/ifconfig |grep br-|cut -d : -f1) promisc on"
        eval "cp -vr ${modifyFilePath}/final_yum_parser_python.py ${baseFolder} ${debug}"
        echo "127.0.0.1 elasticsearch hydra">>/etc/hosts
	#eval "cat <(crontab -l) <(echo '*/10 * * * * /usr/bin/python3 /opt/SIEM/final_yum_parser_python.py') | crontab -"
	eval "echo '*/10 * * * *    root   /usr/bin/python3 /opt/SIEM/final_yum_parser_python.py' > /etc/cron.d/yumCustomLog"
        eval "python3 /opt/SIEM/final_yum_parser_python.py ${debug}"
}

setPromiscMode(){
	eval "yes|cp -vr ${modifyFilePath}/promisc.sh /opt/ ${debug}"
	#eval "cat <(crontab -l) <(echo '@reboot /usr/bin/chmod +x /opt/promisc.sh && /opt/promisc.sh') | crontab -"
	eval "echo '@reboot /usr/bin/chmod +x /opt/promisc.sh && /opt/promisc.sh' >/etc/cron.d/setPromiscMode"
}
openDjangoReport(){
	eval "tar -xvf ${modifyFilePath}/report.tar.gz -C ${baseFolder} ${debug}"
	eval "yes|cp -vr ${baseFolder}/wazuh-docker/production_cluster/ssl_certs/root-ca.pem ${baseFolder}/test/mysite ${debug}"
	export EXTERNAL_IP=$(ifconfig eth0|grep -w inet|awk '{print $2}')
	eval "docker-compose -f /opt/SIEM/test/docker-compose.yml build ${debug}"
	eval "docker-compose -f /opt/SIEM/test/docker-compose.yml up -d${debug}"

}
setPermission(){
	docker exec -it -u 0 $(sudo docker ps -aqf "name=wazuh-docker_elasticsearch_1") chown -R elasticsearch:root /usr/share/elasticsearch/data
	docker exec -it -u 0 $(sudo docker ps -aqf "name=wazuh-docker_elasticsearch-2_1") chown -R elasticsearch:root /usr/share/elasticsearch/data
	docker exec -it -u 0 $(sudo docker ps -aqf "name=wazuh-docker_elasticsearch-3_1") chown -R elasticsearch:root /usr/share/elasticsearch/data
	eval "systemctl restart docker.service"
}
installCurator(){
	eval "rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch ${debug}"
	eval "echo -e '[curator-5]\nname=CentOS/RHEL 7 repository for Elasticsearch Curator 5.x packages\nbaseurl=https://packages.elastic.co/curator/5/centos/7\ngpgcheck=1\ngpgkey=https://packages.elastic.co/GPG-KEY-elasticsearch\nenabled=1'|tee /etc/yum.repos.d/curator.repo ${debug}"
	eval "yum install elasticsearch-curator -y ${debug}"
	eval "mkdir -p ${baseFolder}/curator"
	eval "yes|cp -vr ${modifyFilePath}/curator ${baseFolder}"
	echo "0 0 * * *	  root 	/usr/bin/curator --config ${baseFolder}curator/curator-config.yml ${baseFolder}curator/curator-action.yml >> ${baseFolder}curator/curator.log 2>&1" > /etc/cron.d/curator
}
main() {
if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1;
fi

mkdir -p ${baseFolder}
installPrerequisites
setPromiscMode
installDocker
upAndRunDocker
setPermission
#copyCertificateFromDcoker
installFileBeat
installAuditBeat
installWazuhAgent
installSuricata
installCurator
sleep 2
#importDashboard
openDjangoReport
customYumLog
#rollback
}

main "$@"

