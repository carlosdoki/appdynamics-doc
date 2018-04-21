import xlsxwriter
import json
import requests
import sys
import base64
import xml.etree.ElementTree

host = ''
port = ''
user = ''
password = ''
account = ''
token = ''
cookies = ''

def get_auth(host, port, user, password, account):
    url = 'https://{}:{}/controller/auth'.format(host, port)
    headers = {
        'Authorization': 'Basic ' + base64.b64encode(user + "@" + account + ":" + password)  
    }
    params = (
        ('action', 'login'),
    )
    response = requests.get(url, headers=headers, params=params)
    global token
    global cookies
    cookies = response.cookies 
    token = response.cookies.get("X-CSRF-TOKEN")

    return 0

def get_applications(host, port, user, password, account):
    url = 'https://{}:{}/controller/rest/applications'.format(host, port)
    auth = ('{}@{}'.format(user, account), password)
    #print(auth)
    params = {'output': 'json'}

    #print('Getting apps', url)
    r = requests.get(url, auth=auth, params=params)
    return sorted(r.json(), key=lambda k: k['name'])

def find_dashboard(dashboards, name):
    id = 0
    for i in dashboards:
        if i['name'] == name:
            id = i['id']
            break
    return id

def transaction_auto(worksheet, bold, i, id, name):
    #Transaction
    #https://buscapecompany.saas.appdynamics.com/controller/transactiondetection/5307/auto
    url = 'https://{}:{}/controller/transactiondetection/{}/auto'.format(host, port, id)
    auth = ('{}@{}'.format(user, account), password)
    #print('Getting apps', url)
    r = requests.get(url, auth=auth)
    root = xml.etree.ElementTree.fromstring(r.content)
    
    for child in root:
        if child.tag == 'rule-list':
            for rules in child :
                name_rule = rules.attrib['rule-description']
                for rule in rules:
                    valor = xml.etree.ElementTree.tostring(rule).replace('<tx-match-rule>', '')
                    valor = valor.replace('</tx-match-rule>', '')
                    valor = json.loads(valor)
                    for discovery in valor['txautodiscoveryrule']['autodiscoveryconfigs']:
                        if discovery['namingschemetype'] == 'URI':
                            if discovery['httpautodiscovery']['parturisegments']['numsegments'] != 2:
                                #print('numsegments diferent')
                                worksheet.write( i ,0, name)  
                                worksheet.write( i ,1, name_rule)
                                worksheet.write( i ,8, 'nro segmentos')
                                worksheet.write( i ,9, discovery['httpautodiscovery']['parturisegments']['numsegments'])

                            if discovery['httpautodiscovery']['parturisegments']['type'] != 'FIRST':
                                #print('type diferente')
                                worksheet.write( i ,0, name)
                                worksheet.write( i ,1, name_rule)
                                worksheet.write( i ,6, 'Use the')
                                worksheet.write( i ,7, discovery['httpautodiscovery']['parturisegments']['type'])
    return i

def transaction_custom(worksheet, bold, i, id, name):
    #https://buscapecompany.saas.appdynamics.com/controller/transactiondetection/5307/custom
        #priority="1"  
    url = 'https://{}:{}/controller/transactiondetection/{}/custom'.format(host, port, id)
    auth = ('{}@{}'.format(user, account), password)
    #print('Getting apps', url)
    r = requests.get(url, auth=auth)
    root = xml.etree.ElementTree.fromstring(r.content)
    for child in root:
        if child.tag == 'rule-list':
            for rules in child :
                name_rule = rules.attrib['rule-name']
                if rules.attrib['priority'] != '0':
                    #print("Prioridade diferente 1")
                    for rule in rules:
                        valor = xml.etree.ElementTree.tostring(rule).replace('<tx-match-rule>', '')
                        valor = valor.replace('</tx-match-rule>', '')
                        valor = json.loads(valor)
                        tipo = valor['txcustomrule']['type']
                        entry_point = valor['txcustomrule']['txentrypointtype']
                        for discovery in valor['txcustomrule']['matchconditions']:
                            i = i + 1
                            worksheet.write( i ,0, name)   
                            worksheet.write( i ,1, name_rule)  
                            worksheet.write( i ,2, rules.attrib['priority'])
                            # Write some simple text.
                            worksheet.write( i ,3, tipo)
                            if entry_point == 'SERVLET':
                                worksheet.write( i ,4, discovery['httpmatch']['uri']['type'])
                                worksheet.write( i ,5, discovery['httpmatch']['uri']['matchstrings'][0])
                            if entry_point == 'WEB_SERVICE':
                                worksheet.write( i ,4, discovery['genericmatchcondition']['stringmatchcondition']['type'])
                                worksheet.write( i ,5, discovery['genericmatchcondition']['stringmatchcondition']['matchstrings'][0])
    return i

def health_rules(worksheet, bold, x, id, name):
    #Health Rules
    #https://buscapecompany.saas.appdynamics.com/controller/healthrules/530
    url = 'https://{}:{}/controller/healthrules/{}'.format(host, port, id)
    auth = ('{}@{}'.format(user, account), password)
    #print('Getting apps', url)
    r = requests.get(url, auth=auth)
    root = xml.etree.ElementTree.fromstring(r.content)
    y = 0
    i = x
    health = ''
    health_ant = ''
    for child in root:
        for rules in child :
            if rules.tag == 'name':
                health = rules.text
            if health != health_ant:
                health_ant = health
                if y != 0: 
                    i = i + 1
                y = 0
            if rules.tag == 'duration-min' and rules.text != '30':
                worksheet.write( i ,0, name) 
                worksheet.write( i ,1, health)  
                #print("duration diferente")
                worksheet.write( i ,2, rules.text)

            if rules.tag == 'wait-time-min' and rules.text != '30':
                #print("wait-time-min diferente")
                worksheet.write( i ,0, name) 
                worksheet.write( i ,1, health)  
                worksheet.write( i ,3, rules.text)

            if health == 'Memory utilization is too high' or health == 'JVM Heap utilization is too high':
                if rules.tag == 'warning-execution-criteria':
                    for policys in rules:
                        if policys.tag == 'policy-condition':
                            for policy in policys:
                                if policy.tag == 'condition-value' and policy.text != '75.0':
                                    #print("memoria diferente")
                                    worksheet.write( i ,0, name) 
                                    worksheet.write( i ,1, health)  
                                    worksheet.write( i ,4, policy.text)
                if rules.tag == 'critical-execution-criteria':
                    for policys in rules:
                        if policys.tag == 'policy-condition':
                            for policy in policys:
                                if policy.tag == 'condition-value' and policy.text != '90.0':
                                    #print("memoria diferente")
                                    worksheet.write( i ,0, name) 
                                    worksheet.write( i ,1, health)                              
                                    worksheet.write( i ,5, policy.text)
    return

def process():
    get_auth(host, port, user, password, account)
    APPS = get_applications(host, port, user, password, account)

    # Create an new Excel file and add a worksheet.
    global workbook 
    workbook = xlsxwriter.Workbook('{}.xlsx'.format(account))
    worksheet = workbook.add_worksheet('Transaction Discovery')
    worksheet2 = workbook.add_worksheet('Health Rules')
    bold = workbook.add_format({'bold': True})
    i = 0
    worksheet.write( i , 0, 'Aplicacao', bold) 
    worksheet.write( i , 1, 'Nome', bold)
    worksheet.write( i , 2, 'Prioridade', bold)
    worksheet.write( i , 3, 'Tipo', bold) 
    worksheet.write( i , 4, 'Operador', bold)
    worksheet.write( i , 5, 'Valor', bold)
    i = i + 1
    x = 0
    worksheet2.write( x , 0, 'Aplicacao', bold) 
    worksheet2.write( x , 1, 'Nome', bold)
    worksheet2.write( x , 2, 'duration-min', bold)
    worksheet2.write( x , 3, 'wait-time-min', bold) 
    worksheet2.write( x , 4, 'warning', bold)
    worksheet2.write( x , 5, 'critical', bold)
    x = x + 1

    for application in APPS:
        id = application['id']
        name = application['name']
        print(name)
        # Add a bold format to use to highlight cells.
        
        i = transaction_auto(worksheet, bold, i, id, name)
        i = transaction_custom(worksheet, bold, i, id, name)
        i = i + 1
        health_rules(worksheet2, bold, x, id, name)
        x = x + 1

    workbook.close()


def main():
    global host
    global port
    global user
    global password
    global account

    #try:
    host = sys.argv[1] 
    port = sys.argv[2]
    user = sys.argv[3]
    password = sys.argv[4]
    account = sys.argv[5]

    process()

    #except:
    #    print 'dashboard.py <host> <port> <user> <password> <account> <importacao>'
    #    sys.exit(2)

if __name__ == '__main__':
    main()
