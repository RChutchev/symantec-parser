# Copyright - Roman Chutchev (RChutchev.ru) a.k.a. RChutchev
# FOR INTERNAL USE ONLY - NON PRODUCTION Ver
import configparser
import os
import re


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
    config.read(config_path)
    config.sections()

    if 0 == len(str(config['SEP']['SEP_LOG_FOLDER'])) or 0 == len(config['SEP']['SEP_LOG_NAME']) or 0 == len(
            config['SEP']['ExLOCAL_IPs_MASK']) or 0 == len(config['SEP']['EXCLUDED_IP']) or 0 == len(config['SEP']['NAME_OF_IPs_LIST']):
        # Config ERROR, use defaults settings
        print('Ошибка чтения файла конфигурации')
        sep_path = r'C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs'
        log_name = 'seclog.log'
        LOCAL_IP_MASK = '192.168.'
        Ex_IPs = ["8.8.8.8", "8.8.4.4"]
        PATH_TO_FILE_WITH_IPs = 'C:\PS\\'
        NAME_OF_IPs_LIST = 'iptoblock.txt'
    else:
        # read config
        sep_path = str(config['SEP']['SEP_LOG_FOLDER'])
        log_name = config['SEP']['SEP_LOG_NAME']
        LOCAL_IP_MASK = config['SEP']['ExLOCAL_IPs_MASK']
        Ex_IPs_str = config['SEP']['EXCLUDED_IP']
        Ex_IPs = Ex_IPs_str.split(',')
        PATH_TO_FILE_WITH_IPs = config['SEP']['PATH_TO_FILE_WITH_IPs']
        NAME_OF_IPs_LIST = config['SEP']['NAME_OF_IPs_LIST']

    if check_file_exist(sep_path, log_name):
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
                        ips_file = open(PATH_TO_FILE_WITH_IPs+NAME_OF_IPs_LIST, 'w+')
                        for bad_ip in lst_clear:
                            ips_file.write(bad_ip+'\n')
                        ips_file.close()

        print(len(lst))  # Print count duplicated values FOR DEBUG
        print(len(lst_clear))  # Print final count in list
    else:
        print('No SEP log file')
        exit(666)
else:
    exit(1)
