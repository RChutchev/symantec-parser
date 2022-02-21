# Copyright - Roman Chutchev (RChutchev.ru) a.k.a. RChutchev
# Beta version
import configparser
import os
import re
import sys
import pyautogui


def check_file_exist(path, file_name):
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

    DEBUG = False
    if config.get('SEP', 'DEBUG', fallback=False):
        DEBUG_ENABLED = config.get('SEP', 'DEBUG', fallback=False)
        print(DEBUG_ENABLED)
        if DEBUG_ENABLED == 'True':
            DEBUG = True

    if check_file_exist(sep_path, log_name):
        if DEBUG:
            pyautogui.alert(text="Debug is enabled", title="Attention!")

        log = open(sep_path + '/' + log_name, 'r', encoding='ANSI')
        lines = log.readlines()
        lst = []
        lst_clear = []
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

        # Write to file here
        if len(lst_clear) != 0:
            ips_file = open(PATH_TO_FILE_WITH_IPs + NAME_OF_IPs_LIST, 'w+')
            for bad_ip in lst_clear:
                ips_file.write(bad_ip + '\n')
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
