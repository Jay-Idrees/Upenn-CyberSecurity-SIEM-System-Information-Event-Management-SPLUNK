# SIEM- Security Information and Event Management

- Goals of an organization: confidentiality, integrity and availability
- Attacks are detected by continues monitoring called **Information security continues monitoring- ISCM**

- This is a technology and is principally comprised of two main components.
1. **SIM**- Seurity information management - collecting logs in a central location
2. **SEM**- Security event management- analyzing logs for event monitoring, co-relation and rule creation etc

It is a single software system that help to automatethe processes of **aggregate, parse and normalize** logs

- When logs are loaded into SIEM software, they are automatically parsed and normalized, with all the field headers identified.


## Types of Logs

- Logs contain entties that represent sepecific events occurring on a network or device. **log aggregation** is when the logs are gathered together from multiple sources



1.  **Operating system logs** are created on devices such as `Linux and Windows` systems. 
     Example:` log2.txt` shows linux logs as there are references to `etc/shadow` and adding users etc. and `log4.txt` is a windows system log file

```
SAMPLE LINUX log 

add
change
management",,,,,,"account
add
change
management",,,,,,,,,,,,,,,15,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,"Jan 13 17:26:39 PROD-POS-003  groupadd[114]: group added to /etc/gshadow: name=webalizer
","2020-01-13T17:26:39.000+0000",,,,,,,,17,13,26,july,39,monday,2020,local,"PROD-POS-003",,,,,,,,,false,,,,,,untrust,,false,false,false,,,"groupadd nix-all-logs",,"PROD-POS-003",,main,,,,2,,,webalizer,,,,,,114,,groupadd,,,,,"__::_--__[]:____//:_=",,,,,,,,,syslog,syslog,"prd-p-lvb3bpcl8bts",,"PROD-POS-003",,,,,,,,,false,,,,,,untrust,,,false,,false,false,,,,,,,,,,,,,,,,,,,,,,,,,,"account
add
change
management",,,,,,"account
add
change
management",,,,,,,,,,,,,,,15,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
,,"Jan 13 17:26:03 PROD-MFS-006  groupadd[145]: group added to /etc/group: name=usrpqr
","2020-01-13T17:26:03.000+0000",,,,,,,,17,13,26,july,3,monday,2020,local,"PROD-MFS-006",,,,,,,,,false,,,,,,untrust,,false,false,false,,,"groupadd nix-all-logs",,"PROD-MFS-006",,main,,,,2,,,usrpqr,,,,,,145,,groupadd,,,,,"__::_--__[]:____//:_=",,,,,,,,,syslog,syslog,"prd-p-lvb3bpcl8bts",,"PROD-MFS-006",,,,,,,,,false,,,,,,untrust,,,false,,false,false,,,,,,,,,,,,,,,,,,,,,,,,,,"account
```
Sample Windows logs below
```

   ubject:
	Security ID:		Domain_D\user_d
	Account Name:		user_d
	Account Domain:		Domain_D
	Logon ID:		0x3EC3
Privileges:	SeSecurityPrivilege
			SeTakeOwnershipPrivilege
			SeLoadDriverPrivilege
			SeBackupPrivilege
			SeRestorePrivilege
			SeDebugPrivilege
			SeSystemEnvironmentPrivilege
			SeImpersonatePrivilege",,,,,,,,,,,,,,,Info,,,,,,,,,,,SeSecurityPrivilege,,,,,233354340,,,,,,"Domain_D\user_d",,,"Microsoft Windows security auditing.",,,,,,,,,,,,,,,,,"Special Logon",,,,,Information,,,,,,,,,,,,"01/13/2020 05:41:56 PM
LogName=Security
SourceName=Microsoft Windows security auditing.
EventCode=4672
EventType=0
Type=Information
ComputerName=PROD-POS-005
TaskCategory=Special Logon
OpCode=Info
RecordNumber=233354340
Keywords=Audit Success
Message=Special privileges assigned to new logon.
Subject:
	Security ID:		Domain_D\user_d
	Account Name:		user_d
	Account Domain:		Domain_D
	Logon ID:		0x3EC3
Privileges:	SeSecurityPrivilege
			SeTakeOwnershipPrivilege
			SeLoadDriverPrivilege
			SeBackupPrivilege
			SeRestorePrivilege
			SeDebugPrivilege
			SeSystemEnvironmentPrivilege
			SeImpersonatePrivilige
","2020-01-13T17:41:56.000+0000",success,"win:unknown","Special privileges assigned to new logon.
```

   > Things to watch for in operating logs
   - an unauthorized user attempts to view privileged data, such as a company payroll file.

     - Security permissions events: For example, a user attempts to give themselves permissions to view and edit a privileged file.
    
2. **Application logs** are created by devices such as `Apache and IIS` (Internet Information Services) servers or webserver logs. Example: `log5.txt` gives login/logout activity by a usename
      
```
DATE            IP              USER    ACTIVITY
01/13/19	42.34.65.34	billy	Login
01/13/19	42.34.65.34	billy	Add Items to Cart
01/13/19	42.34.65.34	billy	Checkout
01/13/19	42.34.65.34	billy	Search
01/13/19	42.34.65.34	billy	Logout
```



    > Things to watch for in application logs
      For example, a `brute force attempt` to log into an administrative account on a web application.
      
      - Fraud events: For example, a user on a financial application attempts to transfer a large sum of funds to a suspicious external account.
  
3. **Networking device logs** are created on devices such as `routers, switches, and DHCP/DNS servers`. (DHCP-dynamic host configuration protocol- ) 
    
    > Things to watch for networking device logs
    - Administrative events: For example, a network administrator accidentally opens a `port allowing unauthorized traffic` into a network.
    
    - Network security events: For example, a `DHCP starvation attack` occurs in which the DHCP server receives thousands of requests in a short period of time, `consuming all available IP addresses`.
    
4. **Security device logs** are created on devices such as `IDS/IPS, firewalls, endpoint devices, and honeypots`.  Example: `log1.txt`
```
"2020-01-13T17:21:54.000+0000",detected,,10725,"Oracle.9i.TNS.OneByte.DoS",,"N/A",DoS,,,"DoS: Oracle.9i.TNS.OneByte.DoS",1,,"2019-06-05",17,13,21,Maruary,54,monday,2020,local,"128.241.220.82",,,,,,,,"128.241.220.82",false,,,,,,untrust,1521,,false,,false,false,FG300B3909600791,"FORTINET-01",,"128.241.220.82","PCI-APP-DB",1521,"FORTINET-01",,,,,,,,FG300B3909600791,,false,,,,,,untrust,,false,false,false,,0419016384,"fortinet fortinet_ips",detected,detected,signature,ips,"N/A","127.0.0.1",0,network,"NON-PCI-WEB",651335741,main,,,,2,0419016384,,,"DoS: Oracle.9i.TNS.OneByte.DoS",,,,"PCI-APP-DB",,,302,alert,,IPS,"N/A","N/A","N/A",6,,,"__::_-_=--,=::,=-,=,=,=,=,=,=,=""/"",=""/"",=""/"",=""/"",",,"http://www.fortinet.com/ids/VID10725",,"all_default_pass",1259658504,"1521/tcp",critical,,,"DoS: Oracle.9i.TNS.OneByte.DoS","sample.ips.fortinet",fortinet,"prd-p-lvb3bpcl8bts",,"12.130.60.5",,,,,,,,"NON-PCI-WEB","12.130.60.5",false,,,,,,untrust,13611,,false,,false,false,detected,,signature,"attack
firewall
ids
network",,,,,,"attack
firewall
ids
network",,,,,,,,,,,"13:32:41",16,0,tcp,6,ips,"N/A",,,,,,,,,,,,,,,,,,false,,,,,root,Fortinet,
"Mar 13 17:21:45 fortinet-01 date=2019-06-05,time=14:46:43,devname=FORTINET-01,device_id=FG300B3909600791,log_id=0419016384,type=ips,subtype=signature,pri=alert,severity=medium,carrier_ep=""N/A"",profilegroup=""N/A"",profiletype=""N/A"",profile=""N/A"",src=12.130.60.4,dst=59.162.167.100,src_int=""NON-PCI-WEB"",dst_int=""PCI-APP-DB"",policyid=302,identidx=0,serial=1259985200,status=detected,proto=6,service=1521/tcp,vd=""root"",count=1,attack_name=Oracle.9i.TNS.OneByte.DoS,src_port=59495,dst_port=1521,attack_id=10725,sensor=""all_default_pass"",ref=""http://www.fortinet.com/ids/VID10725"",user=""N/A"",group=""N/A"",incident_serialno=651335750,msg=""DoS: Oracle.9i.TNS.OneByte.DoS""
","2020-01-13T17:21:45.000+0000",detected,,10725,"Oracle.9i.TNS.OneByte.DoS",,"N/A",DoS,,,"DoS: Oracle.9i.TNS.OneByte.DoS",1,,"2019-06-05",17,13,21,Maruary,45,monday,2020,local,"59.162.167.100",,,,,,,,"59.162.167.100",false,,,,,,untrust,1521,,false,,false,false,FG300B3909600791,"FORTINET-01",,"59.162.167.100","PCI-APP-DB",1521,"FORTINET-01",,,,,,,,FG300B3909600791,,false,,,,,,untrust,,false,false,false,,0419016384,"fortinet fortinet_ips",detected,detected,signature,ips,"N/A","127.0.0.1",0,network,"NON-PCI-WEB",651335750,main,,,,2,0419016384,,,"DoS: Oracle.9i.TNS.OneByte.DoS",,,,"PCI-APP-DB",,,302,alert,,IPS,"N/A","N/A","N/A",6,,,"__::_-_=--,=::,=-,=,=,=,=,=,=,=""/"",=""/"",=""/"",=""/"",",,"http://www.fortinet.com/ids/VID10725",,"all_default_pass",1259985200,"1521/tcp",critical,,,"DoS: Oracle.9i.TNS.OneByte.DoS","sample.ips.fortinet",fortinet,"prd-p-lvb3bpcl8bts",,"12.130.60.4",,,,,,,,"NON-PCI-WEB","12.130.60.4",false,,,,,,untrust,59495,,false,,false,false,detected,,signature,"attack
firewall
ids
network",,,,,,"attack
firewall
ids
```

  
    Security events that can be identified by these logs include:
      - Endpoint events: For example, a `user accidentally downloads malware` onto their laptop from a phishing email.

      - IDS signature events: For example, a packet with an `illegal TCP flag` combination is identified by an IDS. TCP flags, such as a SYN packet with the FIN bit set, are illegal and shouldn’t be seen on any network

Logs vary in format: A few examples:

  - Log 1: `User TJones Successfully Authenticated to 10.182.12.35 from client 43.10.8.22` 

  - Log 2: `43.182.12.35 New Client Connection 84.10.8.22  on account: PSmith: Success`

  Not the source and destination ip. 

  As the formats are different for the logs. We can use **log parsing**: Converting a single string as shown above into fields of structured data, Once that is done the logs can be rearranged into a uniform structure called **log normalization**. We may also have to change the timing format to military vs standard 12hr format. Important to note the source and destination ips an the usernames

  - Log 1:  `User |TJones| Successfully Authenticated | to |10.182.12.35 |from client |43.10.8.22|`


- Log 2: `43.182.12.35|  New Client Connection |84.10.8.22|  on account:| PSmith| : Success`

- During aggregation and normalization the goal is to extract the following vital information from the logs:

   - Date: `[17/May/2015:10:05:12 +0000]`
   - IP: `83.149.9.216`
   - Protocol and Version: `HTTP/1.1`
   - Resource Requested: `/presentations/logstash `
   - User Agent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 19_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.23.34.77 Safari/537.36`
   - HTTP Response Code: `200`
   - File Size: `7697`

   ## Creating co-relation rules and alerts
   - Logs have an enormous number of events recorded. Individual events are less helpful, but the in aggregate they can be co-related into meaningful information. This is called **Login co-relation**

   - Based on expected co-relation of certain types of attacks we can define certain rules. It is often easier to pseudocode before getting deep into creating a rule that will create an alert based on detection of a pattern in the logs that is suspiscious

     Detect:
    - More than three "Login Failed" 
    - From the same user
    - From the same IP address
    - Within a five-minute period
 

- For the detection of events in web requests its useful to know the response code- typically 200 is what we are looking for as it means success
- Informational responses (100–199)
- Successful responses (200–299)
- Redirects (300–399)
- Client errors (400–499)
- Server errors (500–599)

1. Create an alert when: There was suspicious and unsuccessful web activity from Beijing.
    - The protocol is HTTP.
    - The HTTP response code is not 200.
    - The source IP is from Beijing.
   
2. Create an alert when: There were floods of web requests from a single source IP in a short period of time.
    - The protocol is HTTP.
    - The same source IP appears more than 50 times within 5 minutes.
    - This is an estimate and the true setting may be adjusted depending on past attacks.
   
3. Create an alert when: There were suspicious successful web requests to access JPG images from IPs outside of the United States.
    - The protocol is HTTP.
    - The response code is 200.
    - The resource contains .jpg in the file name.
    - The IP address is not from the United States.


    **SIEM Vendors**
    
    - RSA NetWitness
    - AlienVault USM
    - ELK
    - IBM Security QRadar
    - MicroFocus ArcSight ESM
    - McAfee Enterprise Security Manager
    - LogRythm 
    - Splunk Enterprise Security
    - Solarwinds Log and Event Manager
    - Securonix

    
2. Answer the following questions about your SIEM vendor selection. Use Google if necessary. 
   - What is the name of the SIEM product you selected?
   - What is the name of the SIEM vendor organization?
   - What are the features of this SIEM?
   - What are the primary advantages of this SIEM ?


   # S P L U N K

Splunk SIEM product is called  **Splunk Enterprise Security** or Splunk ES. Advanced monitoring solutions provide additional benifits such as machine learning, AI, automation and response
**Advanced Monitoring Solutions**
- User behavior analytics **(UBA)** - Detects abnormalities in user activity- trigers alert when a user deviates from typical behaviour

If a user usually only logs onto a server between 9 a.m. and 5 p.m., Monday through Friday, UBA would create an alert if the user logged in on at 2 a.m. on a Saturday.

- User and entity behavior analytics **(UEBA)** - it is expanded UBA to include servers, routers. Creates baseline behaviour and then detects abnormalities

- Security orchestration, automation and response **(SOAR)** Responds to incidents by creating logs and implementing mitigation strategies

- SOAR uses playbooks that dictate respose for typical threats- These can decrease incidence reponse time

   > Splunk commands and queries

  ` source="fortinet_IPS_logs.csv" attack_name="Oracle.9i.TNS.OneByte.DoS"`

`source="fortinet+IPS_log.csv" host="cae59c510a8" sourcetype="csv"

  Add `| stats count as total` to the end of the search and run the search again.

Splunk can create location-specific reports with the `iplocation` and `geostats` commands. 

`sourcetype="stream:http" | iplocation src_ip`

`source="demo_httplogs.csv" | iplocation src_ip | geostats count`

Looking at every thing together

- The volume of successful logins on the website
- The volume of unsuccessful logins on the website
- A geographic map illustrating where the activity is coming from
- A pie chart displaying the specific pages of the website that are being accessed


- A radial gauge of successful logins.
- A pie chart of users logging in.
- A statistical chart of the data in the pie chart.

Splunk tool dashboard displays all the infomation together

`source="demo_winlogs.csv" signature="An account was successfully logged on" | stats count as total`

select save as dashboard pannel

`source="demo_winlogs.csv"| top limit=10 user`

- Then you can keep adding various components to the dashboard by selecting the "existing" dashboard. Note that the dashboards can also be edited

- For each of the pannels you can select the 