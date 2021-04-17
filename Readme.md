# SIEM- Security Information and Event Management

- Goals of an organization: confidentiality, integrity and availability
- Attacks are detected by continues monitoring called **Information security continues monitoring- ISCM**

## Types of Logs

- Logs contain entties that represent sepecific events occurring on a network or device. **log aggregation** is when the logs are gathered together from multiple sources


1.  **Operating system logs** are created on devices such as `Linux and Windows` systems. 
   
   -  For example, an unauthorized user attempts to view privileged data, such as a company payroll file.

     - Security permissions events: For example, a user attempts to give themselves permissions to view and edit a privileged file.
    
2. **Application logs** are created by devices such as `Apache and IIS` (Internet Information Services) servers.
      
      For example, a `brute force attempt` to log into an administrative account on a web application.
      
      - Fraud events: For example, a user on a financial application attempts to transfer a large sum of funds to a suspicious external account.
  
3. **Networking device logs** are created on devices such as `routers, switches, and DHCP/DNS servers`. (DHCP-dynamic host configuration protocol- ) 
    
    - Administrative events: For example, a network administrator accidentally opens a `port allowing unauthorized traffic` into a network.
    
    - Network security events: For example, a `DHCP starvation attack` occurs in which the DHCP server receives thousands of requests in a short period of time, `consuming all available IP addresses`.
    
4. **Security device logs** are created on devices such as `IDS/IPS, firewalls, endpoint devices, and honeypots`. 
  
    Security events that can be identified by these logs include:
      - Endpoint events: For example, a `user accidentally downloads malware` onto their laptop from a phishing email.

      - IDS signature events: For example, a packet with an `illegal TCP flag` combination is identified by an IDS. TCP flags, such as a SYN packet with the FIN bit set, are illegal and shouldn’t be seen on any network

Logs vary in format: A few examples:

  - Log 1: `User TJones Successfully Authenticated to 10.182.12.35 from client 43.10.8.22` 

  - Log 2: `43.182.12.35 New Client Connection 84.10.8.22  on account: PSmith: Success`