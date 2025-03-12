# symantec-parser (ex. sep-seclog-ips-parser)
Symantec Endpoint Protection (SEP) seclog file IP Analyzer

> [!WARNING]  
> **This version may not be suitable for production use!**
> 
> **The package is not being actively maintained, if you want to maintain this package, please reach out!**


Please note that this is a beta version which is used for a personal RDP server with a normal workload.

The script tries to find the attacker's IP addresses in the 'seclog' file and blocks if the number of attacks exceeds a certain number.
All settings are in the settings.ini file.

[!] Pre-set maximum log file size for SEP
![SEP](https://user-images.githubusercontent.com/11131666/160029183-c9ba7846-1b34-4a67-a4a2-2eed5fcbff11.PNG)
[!] Create a predefined rule for auto-update
![SEP FW](https://user-images.githubusercontent.com/11131666/160029695-47c2cb8d-fbcc-49e2-83f5-2431b02757e7.PNG)


SEP firewall rule blocking:
1. Export current rules
2. Add IP addresses to the predefined rule.
4. Import rules into SEP
That's simple but it works fine.


### Please, check all settings in the config file before use.
