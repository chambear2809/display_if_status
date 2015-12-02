#!/usr/bin/env python
'''
Python 2.7.x only
display_if_status


Copyright (C) 2015 Cisco Systems Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

# list of packages that should be imported for this code to work
import re
import sys
import cobra.mit.access
import cobra.mit.session
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings() 

from cobra.mit.session import LoginSession
from cobra.mit.access import MoDirectory

# get an interface name and an index 
# the index is slot_id * 200 + port_id
# assume one slot has no more than 200 ports
def getIfName(intf):

    # phy interface name is like phys-[eth1/98]
    name = None
    idx = None

    match = re.search('\[(eth\d+/\d+)\]', str(intf.dn))
    if match:
        name = match.group(1)
        match = re.search('(\d+)/(\d+)', name)
        if match:
            idx = 200*int(match.group(1)) + int(match.group(2))

    return name, idx 

def login_cli(apicUrl, user, password):
    try:
        loginSession = LoginSession(apicUrl,user,password)
        moDir = MoDirectory(loginSession)
        moDir.login()
    except:
        print "the username and/or password you entered is incorrect"    
    return moDir

def get_lldp_cdp(nodeName,moDir):
    temp1 =""
    temp2 =""
    temp3 =""
    temp4 =""                  
#     for i in range(0,2000):
#         lldp_A = moDir.lookupByClass('lldpIf')
#         lldpIf = lldp_A[i]               
#         for lldpIfi in list(lldp_A[i].dn.rns)[::-1]:
#             print '==================================== i =>',i, lldpIfi.meta.moClassName   
#             pass
#         for lldpIfii in list(lldp_A[i].dn.rns)[::-1]:
#             print '========================================> 2', lldpIfii.meta.moClassName       
#             print '=======tuple(lldpIfii.namingVals)=======> 2', tuple(lldpIfii.namingVals)                    
    try:
        parent_LLDP = moDir.lookupByClass("lldpIf")
        for LLDP in parent_LLDP:                           
            if LLDP.id in nodeName:
                child_LLDP = moDir.lookupByClass("lldpAdjEp", parentDn=LLDP.dn)
                for lldpAdjEp in child_LLDP:
                    if nodeName in str(lldpAdjEp.dn):                                                         # verifiy that is is correct to check    
#                         print '===========1===========','-1',nodeName,'-2',LLDP.dn
                        temp1 = (str(lldpAdjEp.sysName))
                        temp2 = (str(lldpAdjEp.portDesc))
                        temp2 = (re.findall("pathep-(.+)", str(lldpAdjEp.portDesc)))
                        temp2 = str(temp2).strip("[']")

        parent_CDP = moDir.lookupByClass("cdpIf")
        for CDP in parent_CDP:                          
            if CDP.id in nodeName:
                child_CDP = moDir.lookupByClass("cdpAdjEp", parentDn=CDP.dn)                           
                for cdpAdjEp in child_CDP:
                    if nodeName in str(cdpAdjEp.dn):                                                          # verifiy that is is correct to check  
#                         print '======2========= cdpAdjEp.dn =======> ',nodeName,cdpAdjEp.dn  
                        temp3 = (str(cdpAdjEp.devId))
                        temp4 = (str(cdpAdjEp.portId))
    except:
        print
 
    return temp1,temp2,temp3,temp4

def get_list_pods(moDir):
    # Get the list of pods    
    pods = moDir.lookupByClass("fabricPod", parentDn='topology')
    HtmldomainInfo = []

    forHtmlString = ""
    forHtmlString += '<pre>'
    forHtmlString += '<!DOCTYPE>'
    forHtmlString += '<html>'
    forHtmlString += '<head>'
    forHtmlString += '<script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.6.2/jquery.min.js"></script>'
    forHtmlString += '<link rel="shortcut icon" href="/static/favicon.ico" type="image/x-icon">'
    forHtmlString += '<link rel="icon" href="/static/favicon.ico" type="image/x-icon">'
    forHtmlString += '<link href="/static/style.css" rel="stylesheet">'
    forHtmlString += '</head>'
    forHtmlString += '<body>'
    forHtmlString += '<a href="/select_script"><img src="/static/cisco-logo.png" alt="Cisco Logo" width="10%" height="10%" ></a>'
    linez = '<br><b>       Display Parallel Optical Devices (PODs) Interfaces '
    forHtmlString += "<br>"+"<br>"+linez+"<br>"
    HtmldomainInfo.append(forHtmlString)

    for mo in pods:
        print "name = {}".format(mo.rn)
        forHtmlString = ""
        linez = '=================================================================================================='
        forHtmlString += linez+"<br>"
        linez = "name = {}".format(mo.rn)
        forHtmlString += linez+"<br>"
        HtmldomainInfo.append(forHtmlString)

    
    for pod in pods:
        forHtmlString = ""
        linez = '=================================================================================================='
        forHtmlString += linez+"<br>"
        HtmldomainInfo.append(forHtmlString)

        # Get nodes under one pod
        dn = pod.dn
        nodes = moDir.lookupByClass("fabricNode", parentDn=dn)
        for node in nodes:

            nodeIPs = ""
            dDn = str(node.dn)+'/sys'
            nodesIP = moDir.lookupByClass("topSystem", dDn)
            for i in nodesIP:
                nodeIPs = i.oobMgmtAddr
            print "Node ID: {:<15s} Node Name: {:<15s} Role: {:<15s} OOB IP: {:20}".format(node.rn, node.name, node.role, nodeIPs)
            forHtmlString = ""
            linez = "Node ID: {:<15s} Node Name: {:<15s} Role: {:<15s} OOB IP: {:20}".format(node.rn, node.name, node.role, nodeIPs)
            forHtmlString += linez+"<br>"
            HtmldomainInfo.append(forHtmlString)
 
        for node in nodes:
            # Skip APICs and unsupported switches
            if node.role == 'controller' or node.fabricSt != 'active':
                continue

            nodeIPs = ""
            dDn = str(node.dn)+'/sys'
            nodesIP = moDir.lookupByClass("topSystem", dDn)
            for i in nodesIP:
                nodeIPs = i.oobMgmtAddr
            print '=================================================================================================================================================='
            print "\nNode Name      : " + node.name + "\nOOB Node IP: " + nodeIPs
            linez = '=================================================================================================================================================='
            forHtmlString += linez+"<br>"
            linez = "\nNode Name      : " + node.name + "\nOOB Node IP: " + nodeIPs
            forHtmlString += linez+"<br>"
            linez = "\nInterface_Name     Admin_Status     Operational_Status      lldp_sysName          lldp_portDesc         cdp_devId                       cdp_portId"
            forHtmlString += linez+"<br>"
            print '-------------------------------------------------------------------------------------------------------------------------------------------------'
            linez = '-------------------------------------------------------------------------------------------------------------------------------------------------'
            forHtmlString += linez+"<br>"+"<br>"
            HtmldomainInfo.append(forHtmlString)
	    forHtmlString = ""
                            
            # l1PhysIf has the name of interface and admin status
            # ethpmPhysIf has the operation status
            dn = str(node.dn) + '/l1PhysIf'
            q = cobra.mit.request.ClassQuery(dn)
            q.subtree = 'children'
            q.subClassFilter = 'ethpmPhysIf'
            intfs = moDir.query(q)
    
            iftable = {}
            for intf in intfs:
                name, idx = getIfName(intf)
                if name and idx:
                    for child in intf.children:
                        if child.rn == 'phys':
                            iftable[idx] = [name, intf.adminSt, child.operSt]
    
            # print the interface status
            for idx, listOfPod in sorted(iftable.items()):                
                if listOfPod[2] =='up':
                    nodeName = listOfPod[0]
                    ###---------------------------------------------- get_lldp_cdp -----------------------------------------------###
                    temp1,temp2,temp3,temp4 = get_lldp_cdp(nodeName,moDir)                    

                    print "{:18s} {:16s} {:21s} ".format(listOfPod[0], listOfPod[1], listOfPod[2])
                    linez = "{:18s} {:16s} {:21s} ".format(listOfPod[0], listOfPod[1], listOfPod[2])
                    forHtmlString += linez #+"<br>"
                    print "{:2s}{:20s}".format(' ',temp1)
                    linez = "{:2s}{:20s}".format(' ',temp1)
                    forHtmlString += linez #+"<br>"
                    print "{:2s}{:20s}".format(' ',temp2)
                    linez = "{:2s}{:20s}".format(' ',temp2)
                    forHtmlString += linez #+"<br>"
                    print "{:2s}{:30s}".format(' ',temp3)
                    linez = "{:2s}{:30s}".format(' ',temp3)
                    forHtmlString += linez #+"<br>"
                    print "{:2s}{:10s}".format(' ',temp4)
                    linez = "{:2s}{:10s}".format(' ',temp4)
                    forHtmlString += linez+"<br>"+"<br>"
                    HtmldomainInfo.append(forHtmlString)                                       
                else:
                    print "{:18s} {:16s} {:21s}".format(listOfPod[0], listOfPod[1], listOfPod[2])
                    linez = "{:18s} {:16s} {:21s}".format(listOfPod[0], listOfPod[1], listOfPod[2])
                    forHtmlString += linez+"<br>"
                    HtmldomainInfo.append(forHtmlString)
                
#                 linez = '================================================================================='
#                 forHtmlString += linez+"<br>"
#                 linez = "\nNode Name: " + node.name
#                 forHtmlString += linez+"<br>"
#                 HtmldomainInfo.append(forHtmlString)
                forHtmlString = ""
                #forHtmlString += "<br>"
                #HtmldomainInfo.append(forHtmlString)
        
        forHtmlString = ""
        forHtmlString += '<div id="power">'
        forHtmlString += 'Powered By'
        forHtmlString += '<img src="/static/cisco-tac.jpg" alt="Cisco TAC" width="25%" height="25%" >'
        forHtmlString += '</div>'

        forHtmlString += '</body>'
        forHtmlString += '</html>'
        forHtmlString += '</pre>'
        HtmldomainInfo.append(forHtmlString)
        
    return  HtmldomainInfo     

def main(apicIp, user, password):
   moDir = get_list_pods(login_cli('https://'+apicIp,user,password))
   return moDir            

if __name__ == "__main__":
    apicIP, userID, pw = '', '',''
    main(sys.argv[1],sys.argv[2],sys.argv[3])




