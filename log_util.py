import logging as log
import os

if os.name =="posix":  
    log_files = ["central_server_logs.txt","collection_server_logs.txt","agent_logs.txt"]
elif os.name == "nt":
    log_files = ["central_server_logs.txt","collection_server_logs.txt","agent_logs.txt"]


def init(log_file):

    log_file = log_file+".txt"
    if os.path.exists(log_file):
        print("Log file exists")
        log.basicConfig(filename = log_file, level = log.DEBUG)
    else:
        print("Creating log file")  
        f = open(log_file, "w")
        f.close()
        log.debug("Log file created")
        log.basicConfig(filename = log_file, level = log.DEBUG)