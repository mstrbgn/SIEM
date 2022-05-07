try:
    import os
    import sys
    import json

    import elasticsearch
    from elasticsearch import Elasticsearch, helpers
    import pandas as pd
    from ssl import create_default_context     
    print("All modules are loaded")
except Exception as e:
    print("Some module are Missing {}".format(e))
# es = Elasticsearch([{'host':'localhost','port':9200}])
context = create_default_context(cafile="/etc/filebeat/certs/root-ca.pem")
es = Elasticsearch(
    ['elasticsearch'],
    http_auth=('admin', 'SecretPassword'),
    scheme="https",
    port=9201,
    ssl_context=context,
)

if es.ping():
        print('Yay Connect')
else:
        print('Not connected')


if os.path.isfile('record.txt'):
    tailvalue=os.popen('tail -1 ./record.txt')              #84
    tailvalue=int(tailvalue.readline())
    #print(tailvalue,type(tailvalue))
    Transactionid=os.popen('yum history|grep \'|\'|cut -d \'|\' -f1|head -2|tail -1|tr -d "[:blank:]"')   #86
    Transactionid=int(Transactionid.readline())
    #print(Transactionid,type(Transactionid))
    #print('yes file is present')
    for i in range(tailvalue+1,Transactionid+1):     #84,86
        cmd='yum history info {}|sed -n \'/Tran/,$p\'|sed \'$d\' && echo -e "hostname : $(hostname)" && echo -e "@timestamp : $(date -u +\'%Y-%m-%dT%H:%M:%SZ\')"'.format(i)
        stream = os.popen(cmd)
        dict2={}
        output = stream.readlines()
        for line in output:
            if not line.startswith(' ') and not line.startswith('Loading') and not line[0].isdigit():
                    l=[]
                    key=line.split(':',1)[0].strip()
                    dict2[key]=line.strip().split(':',1)[1].strip()
            else:
                    l.append(line.strip())
                    dict2[key]=l
        json_object=json.dumps(dict2,indent=4)
        doc_source=json_object
        es.indices.create(index='yum-package-final', ignore=400)
        res = es.index(index='yum-package-final', doc_type='yum_logs', body=doc_source)
        print(res)
        file2=open('record.txt','a+')
        file2.writelines(str(i)+'\n')
        file2.close()
            
        #print(json_object)
else:
    #print('No file is not present')
    os.popen('echo "1">record.txt')
    tailvalue=os.popen('tail -1 ./record.txt')
    #print(tailvalue.readline())
    tailvalue=int(tailvalue.readline())
    Transactionid=os.popen('yum history|grep \'|\'|cut -d \'|\' -f1|head -2|tail -1|tr -d "[:blank:]"')
    Transactionid=int(Transactionid.readline())
    for i in range(tailvalue,Transactionid+1):
        cmd='yum history info {}|sed -n \'/Tran/,$p\'|sed \'$d\' && echo -e "hostname : $(hostname)" && echo -e "@timestamp : $(date -u +\'%Y-%m-%dT%H:%M:%SZ\')"'.format(i)
        stream = os.popen(cmd)
        dict2={}
        output = stream.readlines()
        for line in output:
            if not line.startswith(' ') and not line.startswith('Loading') and not line[0].isdigit():
                    l=[]
                    key=line.split(':',1)[0].strip()
                    dict2[key]=line.strip().split(':',1)[1].strip()
            else:
                    l.append(line.strip())
                    dict2[key]=l
        json_object=json.dumps(dict2,indent=4)
        doc_source=json_object
        es.indices.create(index='yum-package-final', ignore=400)        
        res = es.index(index='yum-package-final', doc_type='yum_logs', body=doc_source)
        print(res)
        file2=open('record.txt','a+')
        file2.writelines(str(i+1)+'\n')
        file2.close()
        #print(json_object)

