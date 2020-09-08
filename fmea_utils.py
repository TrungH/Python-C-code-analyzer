#!/usr/bin/python
from template import *
import os
import sys
from pprint import pprint
from json import dumps
from collections import OrderedDict


def plenty_info(msg):
    if PLENTY_INFO:
        print( "  [I] " + msg)
        
def info(msg):
    if INFO:
        print ("  [I] " + msg)
        
def debug(msg):
    if DEBUG:
        print ("  [D] " + msg)

#function to sort a nested dictionary:
#Example:
#dict:
#{
#  "test25": {
#    "id": 29,
#    "value": "value8"
#  },
#  "test22": {
#    "id": 87,
#    "value": "value18"
#  },
#  "test3": {
#    "id": 75,
#    "value": "value53"
#  },
#}
#sort_attr = 'id'
#Output:
#sorted_keys = ["test25", "test3", "test22"]

def sortdict(dict, sort_attr):
    sort_keys = sorted(dict, key=lambda x: (dict[x][sort_attr]))
    return (sort_keys)
    
def merge_dict_to_db(db, dict, key):
    if DEBUG: 
        debug( "Merge dict" + dumps(dict, indent=4) + "key:" + key)
    try:
        current_data = db[key]
        temp = current_data.copy()
        temp.update(dict)
    except:
        temp = dict
    if DEBUG: 
        debug( "DB before merge" + dumps(db, indent=4))
    db[key] = temp
    if DEBUG:
        debug( "DB after merge" + dumps(db, indent=4))
    
    
    
def create_folder_if_not_exist(folder_name):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        
def remove_file(file_path):
    if os.path.isfile(file_path):
        os.unlink(file_path)
                
def empty_folder(folder_name):
    for the_file in os.listdir(folder_name):
        file_path = os.path.join(folder_name, the_file)
        try:
            remove_file(file_path)
        except Exception as e:
            pass
   
def list_files_in_folder(folder, file_type=""):
    list_c_files = os.listdir(folder)
    file_list = []
    for f in list_c_files:
        if file_type == "" or f.endswith(file_type):
            f = os.path.join(folder, f)
            file_list.append(f)
    
    return file_list
            
def list_files_in_folder_recursive(folder, file_type=""):
    list_c_files = os.listdir(folder)
    file_list = []
    for f in list_c_files:
        if os.path.isfile(os.path.join(folder, f)):            
            if file_type == "" or f.endswith(file_type):
                f = os.path.join(folder, f)
                file_list.append(f)
        else:
            d = os.path.join(folder, f)
            file_list += list_files_in_folder_recursive(d, file_type)
    
    return file_list