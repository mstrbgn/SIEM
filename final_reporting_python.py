try:
    import os
    import sys
    import json

    import elasticsearch
    from elasticsearch import Elasticsearch
    import pandas as pd
    from ssl import create_default_context     
    print("All modules are loaded")
except Exception as e:
    print("Some module are Missing {}".format(e))
print("1. NIDS logs")
print("2. Command Executed by users logs")
print("3. Users Login Attempts logs")
print("4. File Ingrity logs")
number=int(input("Enter the number from above to fetch records: "))

#es = Elasticsearch([{'host':'localhost','port':9200}])
context = create_default_context(cafile="/etc/filebeat/certs/root-ca.pem")
es = Elasticsearch(
    ['elasticsearch'],
    http_auth=('admin', 'SecretPassword'),
    scheme="https",
    port=9201,
    ssl_context=context,
    timeout=60,
    max_retries=10,
    retry_on_timeout=True
)
if es.ping():
        print('Yay Connect')
else:
        print('Not connected')
if number>=1 and number<=4:
    from_date = input("Enter date in format yyyy-MM-dd(2020-01-02) from: ")
    to_date = input("Enter date in format yyyy-MM-dd(2020-07-10) to: ")
    #suricata logs wazuh
    query1='{"size":10000,"query":{"bool":{"must":[],"filter":[{"multi_match":{"type":"best_fields","query":"suricata","lenient":true}},{"range":{"timestamp":{"gte":"%s","lte":"%s","format":"yyyy-MM-dd"}}}],"should":[],"must_not":[]}},"_source":["@timestamp","agent.name","rule.description","rule.id","data.src_ip","data.dest_ip","data.alert.category"]}'% (from_date,to_date)
    #Command execution by users auditbeat
    query2='{"size":10000,"query":{"bool":{"must":[],"filter":[{"match_phrase":{"event.module":{"query":"auditd"}}},{"exists":{"field":"event.action"}},{"range":{"@timestamp":{"gte":"%s","lte":"%s","format":"yyyy-MM-dd"}}}],"must_not":[{"match_phrase":{"auditd.summary.actor.primary":"unset"}}]}},"_source":["@timestamp","agent.hostname","auditd.summary.actor.primary","auditd.summary.actor.primary","auditd.summary.actor.secondary","auditd.summary.how","auditd.result","process.args","process.executable"]}'% (from_date,to_date)
    #user login attemps filebeat
    query3='{"size":10000,"query":{"bool":{"must":[],"filter":[{"bool":{"filter":[{"bool":{"should":[{"match":{"event.dataset":"system.auth"}}],"minimum_should_match":1}},{"bool":{"should":[{"exists":{"field":"system.auth.ssh.event"}}],"minimum_should_match":1}}]}},{"match_all":{}},{"range":{"@timestamp":{"gte":"%s","lte":"%s","format":"yyyy-MM-dd"}}}],"should":[],"must_not":[]}},"_source":["@timestamp","agent.hostname","user.name","system.auth.ssh.event","system.auth.ssh.method","source.ip"]}'% (from_date,to_date)
    #auditbeat file-integrity module
    query4='{"size":10000,"query":{"bool":{"must":[],"filter":[{"match_all":{}},{"match_all":{}},{"match_phrase":{"event.module":{"query":"file_integrity"}}},{"range":{"@timestamp":{"gte":"%s","lte":"%s","format":"yyyy-MM-dd"}}}],"should":[],"must_not":[]}},"_source":"*"}'% (from_date,to_date)
    if number == 1:         #suricata(wazuh-alerts)
        data = es.search(index="wazuh-alerts-*", body=query1)
        data=data["hits"]["hits"]
        l=[]
        for d1 in data:
            try:
                dict1={}
                dict1["agent.name"] = d1["_source"]["agent"]["name"]
                dict1["rule.description"] = d1["_source"]["rule"]["description"]
                dict1["@timestamp"] = d1["_source"]["@timestamp"]
                dict1["rule.id"] = d1["_source"]["rule"]["id"]
                dict1["data.src_ip"] = d1["_source"]["data"]["src_ip"]
                dict1["data.dest_ip"] = d1["_source"]["data"]["dest_ip"]
                dict1["data.alert.category"] = d1["_source"]["data"]["alert"]["category"]
                l.append(dict1)
            except Exception as e:
                pass
        df1 = pd.DataFrame(l)
        filename='suricata-'+from_date+'-'+to_date+'.csv'
        df1.to_csv(filename)
        print("CSV File Created Successfully!!!!!",filename)
    elif number == 2:        #command Execution by users(auditbeat-*)
        data1=es.search(index="auditbeat-*",body=query2)
        data1=data1["hits"]["hits"]
        l1=[]
        for d1 in data1:
            try:
                dict2={}
                dict2["@timestamp"] = d1["_source"]["@timestamp"]
                dict2["agent.hostname"] = d1["_source"]["agent"]["hostname"]
                dict2["auditd.summary.actor.primary"] = d1['_source']['auditd']["summary"]["actor"]["primary"]
                dict2["auditd.summary.actor.secondary"] = d1['_source']['auditd']["summary"]["actor"]["primary"]
                dict2["auditd.summary.how"] = d1['_source']["auditd"]["summary"]["how"]
                dict2["auditd.result"] = d1['_source']["auditd"]["result"]
                dict2["process.executable"] = d1['_source']["process"]["executable"]
                l1.append(dict2)
            except Exception as e:
                pass
        df2=pd.DataFrame(l1)
        filename='auditbeat-command-Execution-by-users-'+from_date+'-'+to_date+'.csv'
        df2.to_csv(filename)
        print("CSV File Created Successfully!!!!!",filename)
    elif number == 3:        # Users Failed Login attemps(filebeat-*)
        data2=es.search(index="filebeat-*",body=query3)
        data2=data2["hits"]["hits"]
        l2=[]
        for d1 in data2:
            try:
                dict3={}
                dict3["@timestamp"] = d1["_source"]["@timestamp"]
                dict3["agent.hostname"] = d1["_source"]["agent"]["hostname"]
                dict3["user.name"] = d1['_source']['user']['name']
                dict3["system.auth.ssh.event"] = d1['_source']['system']['auth']['ssh']['event']
                dict3["system.auth.ssh.method"] = d1['_source']['system']['auth']['ssh']['method']
                dict3["source.ip"] = d1['_source']['source']['ip']
                l2.append(dict3)
            except Exception as e:
                pass
        df3=pd.DataFrame(l2)
        filename='filebeat-users-logins-attemps'+from_date+'-'+to_date+'.csv'
        df3.to_csv(filename)
        print("CSV File Created Successfully!!!!!",filename)
    elif number == 4:        #File Intigrity modules (auditbeat1-*)
        data3=es.search(index="auditbeat-*",body=query4)
        data3=data3["hits"]["hits"]
        l3=[]
        for d1 in data3:
            try:    
                dict4={}
                dict4["@timestamp"] = d1["_source"]["@timestamp"]
                dict4["agent.hostname"] = d1["_source"]["agent"]["hostname"]
                #dict4["file.owner"]= d1['_source']['file']['owner']
                dict4["file.path"]=d1['_source']['file']['path']
                dict4["event.category.action"]=d1['_source']['event']['action']    
                dict4["event.category"]=d1['_source']['event']['category']
                l3.append(dict4)
            except Exception as e:
                pass
        df4=pd.DataFrame(l3)
        filename='auditbeat-File-Intigrity-module'+from_date+'-'+to_date+'.csv'
        df4.to_csv(filename)
        print("CSV File Created Successfully!!!!!",filename)
        
else:
    print("Error!!!!!!!!!!!!!!!!!!1")
    print("Please Enter valid a number the range of 1 to 4")
