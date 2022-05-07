#!/bin/bash

debug='>> /var/log/clean.log 2>&1'

#Clean Filebeat
cleanFilebeat(){
eval "rm -rf /etc/filebeat* ${debug}"
eval "rm -rf /usr/share/filebeat* ${debug}"
eval "rm -rf /usr/lib/filebeat* ${debug}"
eval "rm -rf /var/log/filebeat* ${debug}"
eval "rm -rf /etc/rc.d/init.d/filebeat ${debug}"
eval "rm -rf /usr/bin/filebeat* ${debug}"
eval "rm -rf /usr/lib/systemd/system/filebeat.service ${debug}"
eval "rm -rf /etc/systemd/system/multi-user.target.wants/filebeat.service ${debug}"
eval "yum remove filebeat -y ${debug}"
}

#Clean Auditbeat
cleanAuditbeat(){
eval "rm -rf /etc/auditbeat* ${debug}"
eval "rm -rf /usr/share/auditbeat* ${debug}"
eval "rm -rf /usr/lib/auditbeat* ${debug}"
eval "rm -rf /var/log/auditbeat* ${debug}"
eval "rm -rf /etc/rc.d/init.d/auditbeat ${debug}"
eval "rm -rf /usr/bin/auditbeat* ${debug}"
eval "rm -rf /usr/lib/systemd/system/auditbeat.service ${debug}"
eval "rm -rf /etc/systemd/system/multi-user.target.wants/auditbeat.service ${debug}"
eval "yum remove auditbeat -y ${debug}"
}

#Clean wazuh-agent
cleanWazuhAgent(){
eval "rm -rf /var/ossec ${debug}"
eval "rm -rf /etc/systemd/system/multi-user.target.wants/wazuh-agent.service ${debug}"
eval "rm -rf /usr/lib/systemd/system/wazuh-agent.service ${debug}"
eval "rm -rf /var/ossec/bin/wazuh-agentd ${debug}"
eval "yum remove wazuh-agent -y ${debug}"
}

#Clean Docker Container
cleanDocker(){
eval "docker container rm -f \$(docker container ls -aq) ${debug}"
eval "docker network rm wazuh-docker_default ${debug}"
}

cleanCron(){
eval "rm -f /etc/cron.d/yumCustomLog ${debug}"
eval "rm -f /etc/cron.d/curator ${debug}"
eval "rm -f /etc/cron.d/setPromiscMode ${debug}"
}



main(){
cleanFilebeat
cleanAuditbeat
cleanWazuhAgent
cleanCron
cleanDocker
}
main "$@"
