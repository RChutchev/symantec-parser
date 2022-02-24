# Copyright - Roman Chutchev (RChutchev.ru) a.k.a. RChutchev
# version 1.0 Beta - Release
# INFO: settings.ini file REQUIRED in folder with .py or .exe
import configparser
import os
import re
import sys
import pyautogui
import xml.etree.cElementTree as xmlET


def check_file_exist(path, file_name):
    # First: path - is path to folder
    # Second: file_name - is name of file in path folder
    # Return bool
    # True if file exist, False if file is not found.
    if path and file_name is not None:
        f_name = str(path) + '\\' + str(file_name)
        f_result = os.path.isfile(f_name)
    else:
        f_result = False
    return f_result


if __name__ == "__main__":
    config_path = os.path.join(os.getcwd(), 'settings.ini')
    config = configparser.ConfigParser()

    if not check_file_exist(os.getcwd(), 'settings.ini'):
        pyautogui.alert(text="Configuration (settings.ini) file not found!", title="Error!")
        sys.exit(1)

    try:
        config.read(config_path)
        config.sections()
    except configparser.NoSectionError as e:
        # TODO: Check - may not work
        pyautogui.alert(text="Configuration (settings.ini) file error! \n No SEP section.", title="Error!")
        sys.exit(1)

    sep_path = str(config.get('SEP', 'SEP_LOG_FOLDER',
                              fallback=r'C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs'))
    log_name = config.get('SEP', 'SEP_LOG_NAME',
                          fallback='seclog.log')
    LOCAL_IP_MASK = config.get('SEP', 'ExLOCAL_IPs_MASK',
                               fallback='192.168.')
    Ex_IPs_str = config.get('SEP', 'EXCLUDED_IP',
                            fallback=None)
    if Ex_IPs_str is not None and len(Ex_IPs_str) != 0:
        Ex_IPs = Ex_IPs_str.split(',')
    else:
        Ex_IPs = ["8.8.8.8", "8.8.4.4"]
    PATH_TO_FILE_WITH_IPs = config.get('SEP', 'PATH_TO_FILE_WITH_IPs',
                                       fallback=r'C:\\PS\\')
    NAME_OF_IPs_LIST = config.get('SEP', 'NAME_OF_IPs_LIST',
                                  fallback=r'iptoblock.txt')
    IPsListDelimiter = config.get('SEP', 'IPsListDelimiter',
                                  fallback="\n")
    COUNT_TO_BLOCK = config.get('SEP', 'COUNT_TO_BLOCK',
                                fallback="2")
    NAME_OF_SEP_RULE = config.get('SEP', 'NAME_OF_SEP_RULE',
                                  fallback="THIS RULE WILL BE UPDATED AUTOMATICALLY")
    NAME_XML_FROM_SEP = config.get('SEP', 'NAME_XML_FROM_SEP',
                                   fallback=r'rules.xml')
    NAME_XML_FOR_SEP = config.get('SEP', 'NAME_XML_FOR_SEP',
                                  fallback=r'IPs_to_SEP.xml')

    DEBUG = False
    if config.get('SEP', 'DEBUG', fallback=False):
        DEBUG_ENABLED = config.get('SEP', 'DEBUG', fallback=False)
        if DEBUG_ENABLED == 'True':
            DEBUG = True
    DO_NOT_WRITE_LIST = False
    if config.get('SEP', 'DO_NOT_WRITE_LIST_OF_IPs', fallback=False):
        DO_NOT_WRITE_LIST_OF_IPs = config.get('SEP', 'DO_NOT_WRITE_LIST_OF_IPs', fallback=False)
        if DO_NOT_WRITE_LIST_OF_IPs == 'True':
            DO_NOT_WRITE_LIST = True

    if not check_file_exist(PATH_TO_FILE_WITH_IPs, NAME_XML_FROM_SEP):
        pyautogui.alert(text="No SEP exported rules found.", title="Error!")
        sys.exit(1)

    if check_file_exist(sep_path, log_name):
        if DEBUG:
            pyautogui.alert(text="Debug is enabled", title="Attention!")

        log = open(sep_path + '/' + log_name, 'r', encoding='ANSI')
        lines = log.readlines()
        lst = []
        lst_clear = []
        two_or_more = []
        for line in lines:
            # print("Line{}: {}".format(count, line.strip()))
            pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            line = line.rstrip()
            result = pattern.search(line)
            if result is not None:  # Exclude none value
                if not result[1].startswith(LOCAL_IP_MASK):  # Exclude LOCAL IP ex. 192.168.***.***
                    if not any(ip in result[1] for ip in Ex_IPs):  # Exclude from Settings.ini
                        lst.append(result[1])  # Append to list - Result with duplicates
                lst_clear = list(dict.fromkeys(lst))  # Final result list w/o duplicates

        for ip_for_ban in lst:
            if lst.count(ip_for_ban) >= int(COUNT_TO_BLOCK):
                two_or_more.append(ip_for_ban)

        lst_clear_to_ban = list(dict.fromkeys(two_or_more))
        # USE lst_clear_to_ban IPs to add to SEP for permanent block
        # Read XML file here
        tree = xmlET.parse(PATH_TO_FILE_WITH_IPs + NAME_XML_FROM_SEP)
        AdvancedRule = tree.find(f"AdvancedRule[@Description='{NAME_OF_SEP_RULE}']")
        to_add = {}
        for ip in lst_clear_to_ban:
            to_add["Start"] = ip
            to_add["End"] = ip
            HostGroup = AdvancedRule.find('HostGroup')
            Rule = HostGroup.find(f"IpRange[@Start='{ip}']")
            if Rule is None:
                IPRange = xmlET.SubElement(HostGroup, 'IpRange', attrib=to_add)
        # Write to XML file here
        tree.write(PATH_TO_FILE_WITH_IPs + NAME_XML_FOR_SEP)

        # Write to text file here
        if len(lst_clear) != 0:
            if not DO_NOT_WRITE_LIST:
                ips_file = open(PATH_TO_FILE_WITH_IPs + NAME_OF_IPs_LIST, 'w+')
                for bad_ip in lst_clear:
                    ips_file.write(bad_ip + IPsListDelimiter)
                ips_file.close()
            if DEBUG:
                pyautogui.alert(text="Found: " + str(len(lst_clear)) + ' IPs', title="INFO")
                pyautogui.alert(text="File saved!", title="INFO")
        else:
            if DEBUG:
                pyautogui.alert(text="No IPs found! " + str(len(lst_clear)) + ' IPs', title="INFO")

        print(len(lst))  # Print count duplicated values FOR DEBUG
        print(len(lst_clear))  # Print final count in list
    else:
        pyautogui.alert(text="No SEP log file", title="Error!")
