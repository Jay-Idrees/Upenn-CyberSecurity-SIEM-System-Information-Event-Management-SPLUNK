## Solution Guide: What is this Log?

In this activity, you had to analyze logs and determine which type of data they contained, as well as what security events they can help identify.

---

**Log File 1**  
  - File type: Fortinet IDS logs.
  - How this was determined: There are many references to "IDS" and "Fortinet" in the logs.
  - Type of security events: Monitors suspicious network activity such as DOS attacks.

**Log File 2** 
  - File type: Linux syslog.
  - How this was determined: There are references to groups being added to the `/etc/gshadow` file.
  - Type of security events: Identifying suspicious activity within a Linux OS, such as adding suspicious users or groups.

**Log File 3** 
  - File type: Webserver logs.
  - How this was determined: There are references to HTTP activity requests as well as HTTP response codes.
  - Type of security events: Identifying if suspicious IP addresses are trying to access web applications.

**Log File 4** 
  - File type: Windows security event logs.
  - How this was determined: Log record clearly shows "SourceName=Microsoft Windows security auditing."
  - Type of security events: Identifying credential misuse and brute force attempts.

**Log File 5** 
  - File type: Application logs.
  - How this was determined: The logs show activity of logging in and out, and other activity from an application.
  - Type of security events: Identifying brute force attempts and fraud identification.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  