taskkill -IM block.exe /f
cd C:\ps\
main.exe
timeout 5
cd C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\
smc.exe -exportadvrule C:\ps\rules.xml
timeout 5
smc.exe -importadvrule C:\ps\rules_to_SEP.xml