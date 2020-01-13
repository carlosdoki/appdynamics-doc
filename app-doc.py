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
    url = '{}:{}/controller/auth'.format(host, port)
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
    url = '{}:{}/controller/rest/applications'.format(host, port)
    auth = ('{}@{}'.format(user, account), password)
    params = {'output': 'json'}

    print('Getting apps', url)
    r = requests.get(url, auth=auth, params=params)
    if r.status_code != 200:
        print('Erro de conexao, return code=', r.status_code)
        sys.exit(2)
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
    url = '{}:{}/controller/transactiondetection/{}/auto'.format(host, port, id)
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
                        if discovery['txentrypointtype']  != 'WEB':
                            if discovery['namingschemetype'] == 'URI':
                                if discovery['httpautodiscovery']['parturisegments']['numsegments'] > 2:
                                    #print('numsegments diferent')
                                    worksheet.write( i ,0, name)  
                                    worksheet.write( i ,1, name_rule)
                                    worksheet.write( i ,8, 'nro segmentos')
                                    worksheet.write( i ,9, discovery['httpautodiscovery']['parturisegments']['numsegments'])
                                # else:
                                #     worksheet.write( i ,0, name)  
                                #     worksheet.write( i ,1, name_rule)
                                #     worksheet.write( i ,8, 'nro segmentos')
                                #     worksheet.write( i ,9, "2")
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
    url = '{}:{}/controller/transactiondetection/{}/custom'.format(host, port, id)
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
                        i = i + 1
                        wcf1 = 0
                        for discovery in valor['txcustomrule']['matchconditions']:
                            worksheet.write( i ,0, name)   
                            worksheet.write( i ,1, name_rule)  
                            worksheet.write( i ,2, rules.attrib['priority'])
                            # Write some simple text.
                            worksheet.write( i ,3, tipo)
                            #print(discovery)
                            print(entry_point)
                            if entry_point == 'SERVLET' or entry_point == 'WEB' or entry_point == 'NODEJS_WEB':
                                try:
                                    try:
                                        worksheet.write( i ,9, discovery['httpmatch']['httpmethod'])
                                    except Exception as e:
                                        print("")
                                    worksheet.write( i ,4, discovery['httpmatch']['uri']['type'])
                                    worksheet.write( i ,5, discovery['httpmatch']['uri']['matchstrings'][0])
                                    try:
                                        worksheet.write( i ,6, discovery['httpmatch']['parameters'][0]['value']['matchstrings'][0])
                                    except Exception as e:
                                        print("")
                                    try:
                                         worksheet.write( i ,6, discovery['httpmatch']['classmatch']['type'])
                                         worksheet.write( i ,8, discovery['httpmatch']['classmatch']['classnamecondition']['matchstrings'][0])
                                         worksheet.write( i ,7, discovery['httpmatch']['classmatch']['classnamecondition']['type'])
                                    except Exception as e:
                                        print("")
                                except:
                                    try:
                                        worksheet.write( i ,6, discovery['httpmatch']['classmatch']['type'])
                                        worksheet.write( i ,8, discovery['httpmatch']['classmatch']['classnamecondition']['matchstrings'][0])
                                        worksheet.write( i ,7, discovery['httpmatch']['classmatch']['classnamecondition']['type'])
                                    except:
                                        worksheet.write( i ,4, "headers")
                                        worksheet.write( i ,6, discovery['httpmatch']['headers'][0]['comparisontype'])
                                        worksheet.write( i ,8, discovery['httpmatch']['headers'][0]['value']['matchstrings'][0])
                                        worksheet.write( i ,7, discovery['httpmatch']['headers'][0]['value']['type'])
                            
                            if entry_point == 'WEB_SERVICE':
                                worksheet.write( i ,4, discovery['genericmatchcondition']['stringmatchcondition']['type'])
                                worksheet.write( i ,5, discovery['genericmatchcondition']['stringmatchcondition']['matchstrings'][0])
                            if entry_point == 'POCO' or entry_point == 'POJO':
                                print(discovery)
                                worksheet.write( i ,5, "POJO")
                                worksheet.write( i ,4, discovery['instrumentionprobe']['javadefinition']['classmatch']['type'])
                                worksheet.write( i ,6, discovery['instrumentionprobe']['javadefinition']['classmatch']['classnamecondition']['matchstrings'][0])
                                try:
                                    worksheet.write( i ,7, discovery['instrumentionprobe']['javadefinition']['methodmatch']['methodnamecondition']['matchstrings'][0])
                                except Exception as e:
                                    print("")
                            if entry_point == 'ASP_DOTNET':
                                try:
                                    worksheet.write( i ,9, discovery['httpmatch']['httpmethod'])
                                except Exception as e:
                                    print("")
                                worksheet.write( i ,4, discovery['httpmatch']['uri']['type'])
                                worksheet.write( i ,5, discovery['httpmatch']['uri']['matchstrings'][0])
                            if entry_point == 'WCF':
                                worksheet.write( i ,5, "WCF")
                                try:
                                    worksheet.write( i ,9, discovery['genericmatchcondition']['stringmatchcondition'])
                                except Exception as e:
                                    print("")
                                if wcf1 == 0:
                                    worksheet.write( i ,6, discovery['genericmatchcondition']['stringmatchcondition']['matchstrings'][0])
                                    wcf1 +=1
                                else:
                                    worksheet.write( i ,7, discovery['genericmatchcondition']['stringmatchcondition']['matchstrings'][0])
                                    wcf1 = 0
                                    # i += 1
                            else:
                                i += 1

                        try: 
                            if valor['txcustomrule']['actions'][0] != '':
                                worksheet.write( i ,8, valor['txcustomrule']['actions'][0]['pojosplit']['advancedsplitconfig'][0]['splitoperation'])
                                worksheet.write( i ,9, valor['txcustomrule']['actions'][0]['pojosplit']['excludes']['matchstrings'][0])
                        except:
                            pass
    return i

def health_rules(worksheet, bold, x, id, name):
    #Health Rules
    #https://buscapecompany.saas.appdynamics.com/controller/healthrules/530
    url = '{}:{}/controller/healthrules/{}'.format(host, port, id)
    auth = ('{}@{}'.format(user, account), password)
    #print('Getting apps', url)
    r = requests.get(url, auth=auth)
    #print(r.text)
    root = xml.etree.ElementTree.fromstring(r.content)
    y = 0
    i = x
    health = ''
    health_ant = ''

    for ahealth_rules in root:
        i += 1
        for health_rule in ahealth_rules:
            if health_rule.tag == 'name':
                health = health_rule.text
            # if health != health_ant:
            #     health_ant = health
            #     if y != 0: 
            #     y = 0
            # print("*************")
            #print(health)
            #print(health_rule.tag)

            if health_rule.tag == 'type':
                tipo = health_rule.text
            if health_rule.tag == 'enabled':
                worksheet.write( i ,0, name) 
                worksheet.write( i ,1, health)
                worksheet.write( i ,2, tipo)  
                #print("duration diferente")
                worksheet.write( i ,3, health_rule.text)

            if health_rule.tag == 'duration-min':
                worksheet.write( i ,0, name) 
                worksheet.write( i ,1, health)
                worksheet.write( i ,2, tipo)    
                #print("duration diferente")
                worksheet.write( i ,4, health_rule.text)

            if health_rule.tag == 'wait-time-min':
                #print("wait-time-min diferente")
                worksheet.write( i ,0, name) 
                worksheet.write( i ,1, health)  
                worksheet.write( i ,2, tipo)  
                worksheet.write( i ,5, health_rule.text)

            if health_rule.tag == 'affected-entities-match-criteria':
                for affected_entities_match_criteria in health_rule:
                    for affected_bt_match_criteria in affected_entities_match_criteria:
                        if affected_bt_match_criteria.tag == 'type':
                            tipo2 = affected_bt_match_criteria.text
                        if affected_bt_match_criteria.tag == 'business-transactions':
                            for business_transaction in affected_bt_match_criteria:
                                worksheet.write( i ,0, name) 
                                worksheet.write( i ,1, health)  
                                worksheet.write( i ,2, tipo)
                                # worksheet.write( i ,3, tipo2)
                                worksheet.write( i ,8, business_transaction.text)  
                        if affected_bt_match_criteria.tag == 'node-match-criteria':
                            for node_match_criteria in affected_bt_match_criteria:
                                worksheet.write( i ,0, name) 
                                worksheet.write( i ,1, health)  
                                worksheet.write( i ,2, tipo)
                                # # worksheet.write( i ,3, tipo2)
                                #worksheet.write( i ,8, node_match_criteria.type)  
                                worksheet.write( i ,8, "Node")  


            #if health == 'Memory utilization is too high' or health == 'JVM Heap utilization is too high':
            if health_rule.tag == 'warning-execution-criteria':
                for warning_execution_criteria in health_rule:
                    if warning_execution_criteria.tag == 'policy-condition':
                        for policy_condition in warning_execution_criteria:
                            worksheet.write( i ,0, name) 
                            worksheet.write( i ,1, health)
                            worksheet.write( i ,2, tipo)
                            if policy_condition.tag == 'display-name':
                                worksheet.write( i ,6, policy_condition.text)
                            if policy_condition.tag == 'condition-value-type':
                                worksheet.write( i ,14, policy_condition.text)
                            if policy_condition.tag == 'condition-value':
                                worksheet.write( i ,13, policy_condition.text)
                            if policy_condition.tag == 'operator':
                                worksheet.write( i ,12, policy_condition.text)
                            if policy_condition.tag == 'use-active-baseline':
                                worksheet.write( i ,15, policy_condition.text)
                            if policy_condition.tag == 'condition1':
                                for condition1 in policy_condition:
                                    if condition1.tag == 'display-name':
                                        worksheet.write( i ,6, condition1.text)
                                    if condition1.tag == 'condition-value-type':
                                        worksheet.write( i ,14, condition1.text)
                                    if condition1.tag == 'condition-value':
                                        worksheet.write( i ,13, condition1.text)
                                    if condition1.tag == 'operator':
                                        worksheet.write( i ,12, condition1.text)
                                    if condition1.tag == 'use-active-baseline':
                                        worksheet.write( i ,15, condition1.text)
                                    if condition1.tag == 'metric-expression':
                                        for metric_expression in condition1:
                                            # if metric_expression.tag == 'function-type':
                                            #     worksheet.write( i ,11, metric_expression.text) 
                                            if metric_expression.tag == 'metric-definition':
                                                for metric_definition in metric_expression:
                                                    # if metric_definition.tag == 'type':
                                                    #     worksheet.write( i ,12, metric_definition.text) 
                                                    if metric_definition.tag == 'logical-metric-name':
                                                        worksheet.write( i ,16, metric_definition.text) 
                            if policy_condition.tag == 'metric-expression':
                                for metric_expression in policy_condition:
                                    # if metric_expression.tag == 'function-type':
                                    #     worksheet.write( i ,11, metric_expression.text) 
                                    if metric_expression.tag == 'metric-definition':
                                        for metric_definition in metric_expression:
                                            # if metric_definition.tag == 'type':
                                            #     worksheet.write( i ,12, metric_definition.text) 
                                            if metric_definition.tag == 'logical-metric-name':
                                                worksheet.write( i ,16, metric_definition.text) 
            if health_rule.tag == 'critical-execution-criteria':
                for critical_execution_criteria in health_rule:
                    if critical_execution_criteria.tag == 'policy-condition':
                        for policy_condition in critical_execution_criteria:
                            worksheet.write( i ,0, name) 
                            worksheet.write( i ,1, health)
                            worksheet.write( i ,2, tipo)
                            if policy_condition.tag == 'display-name':
                                worksheet.write( i ,6, policy_condition.text)
                            if policy_condition.tag == 'condition-value-type':
                                worksheet.write( i ,9, policy_condition.text)
                            if policy_condition.tag == 'condition-value':
                                worksheet.write( i ,8, policy_condition.text)
                            if policy_condition.tag == 'operator':
                                worksheet.write( i ,7, policy_condition.text)
                            if policy_condition.tag == 'use-active-baseline':
                                worksheet.write( i ,10, policy_condition.text)
                            if policy_condition.tag == 'condition1':
                                for condition1 in policy_condition:
                                    if condition1.tag == 'display-name':
                                        worksheet.write( i ,6, condition1.text)
                                    if condition1.tag == 'condition-value-type':
                                        worksheet.write( i ,9, condition1.text)
                                    if condition1.tag == 'condition-value':
                                        worksheet.write( i ,8, condition1.text)
                                    if condition1.tag == 'operator':
                                        worksheet.write( i ,7, condition1.text)
                                    if condition1.tag == 'use-active-baseline':
                                        worksheet.write( i ,10, condition1.text)
                                    if condition1.tag == 'metric-expression':
                                        for metric_expression in condition1:
                                            # if metric_expression.tag == 'function-type':
                                            #     worksheet.write( i ,11, metric_expression.text) 
                                            if metric_expression.tag == 'metric-definition':
                                                for metric_definition in metric_expression:
                                                    # if metric_definition.tag == 'type':
                                                    #     worksheet.write( i ,12, metric_definition.text) 
                                                    if metric_definition.tag == 'logical-metric-name':
                                                        worksheet.write( i ,11, metric_definition.text) 
                            if policy_condition.tag == 'metric-expression':
                                for metric_expression in policy_condition:
                                    # if metric_expression.tag == 'function-type':
                                    #     worksheet.write( i ,11, metric_expression.text) 
                                    if metric_expression.tag == 'metric-definition':
                                        for metric_definition in metric_expression:
                                            # if metric_definition.tag == 'type':
                                            #     worksheet.write( i ,12, metric_definition.text) 
                                            if metric_definition.tag == 'logical-metric-name':
                                                worksheet.write( i ,11, metric_definition.text) 
                            
                                

    return i

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
    worksheet.write( i , 6, 'Classe', bold)
    worksheet.write( i , 7, 'Metodo', bold)
    worksheet.write( i , 8, 'Propriedade', bold)
    worksheet.write( i , 9, 'Label', bold)

    i = i + 1
    x = 0
    #critical
    worksheet2.write( x , 7, 'Critical', bold)
    #warning
    worksheet2.write( x , 12, 'Warning', bold)
    x = x + 1

    worksheet2.write( x , 0, 'Aplicacao', bold) 
    worksheet2.write( x , 1, 'Nome', bold)
    worksheet2.write( x , 2, 'Tipo', bold)
    worksheet2.write( x , 3, 'Ativo', bold)
    worksheet2.write( x , 4, 'duration-min', bold)
    worksheet2.write( x , 5, 'wait-time-min', bold) 
    worksheet2.write( x , 6, 'display name', bold)
    #critical
    worksheet2.write( x , 7, 'Operador', bold)
    worksheet2.write( x , 8, 'Valor', bold)
    worksheet2.write( x , 9, 'Tipo Condicao', bold)
    worksheet2.write( x , 10, 'Default Baseline', bold)
    worksheet2.write( x , 11, 'Metrica', bold)
    #warning
    worksheet2.write( x , 12, 'Operador', bold)
    worksheet2.write( x , 13, 'Valor', bold)
    worksheet2.write( x , 14, 'Tipo Condicao', bold)
    worksheet2.write( x , 15, 'Default Baseline', bold)
    worksheet2.write( x , 16, 'Metrica', bold)
    x = x + 1

    for application in APPS:
        id = application['id']
        name = application['name']
        print(name)
        # if name == "PLAT-RM-T51958-RFRANCO-PROD":
        # Add a bold format to use to highlight cells.

        i = transaction_auto(worksheet, bold, i, id, name)
        i = transaction_custom(worksheet, bold, i, id, name)
        # i = i + 1
        x = health_rules(worksheet2, bold, x, id, name)
        # x = x + 1

    workbook.close()


def main():
    global host
    global port
    global user
    global password
    global account

    if len(sys.argv) > 4:
        host = sys.argv[1] 
        port = sys.argv[2]
        user = sys.argv[3]
        password = sys.argv[4]
        account = sys.argv[5]

        process()

    else:
       print 'app-doc.py <http(s)://host> <port> <user> <password> <account>'
       sys.exit(2)

if __name__ == '__main__':
    main()
