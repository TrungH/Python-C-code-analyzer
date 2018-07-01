#!/usr/bin/python
from pprint import pprint
import sys
from template import *
import json
from fmea_utils import *
import re

class Configuration:
    def __init__(self):
        self.module_name    = ""
        self.db             = FMEA_DB
        self.json_file      = FMEA_JSON
        self.source         = SOURCE_DIR
        self.output         = OUTDIR
        self.cvs_out        = OUT_CSV
        self.start_index    = ID_START_INDEX
        self.id_pattern     = ID_PATTERN
        self.volatile_json  = VOLATILE_JSON
        self.inc_dir        = INC_DIR
        self.sort_key       = FMEA_SORT_KEY
        self.csv_template   = OUT_IMPORT_CSV
        self.total_api      = 0
        self.func_call_db   = FUNC_CALL_DB
        self.func_call_json = FUNC_CALL_JSON
        self.graph_dot      = CALL_GRAPH_DOT
        self.graph_img      = CALL_GRAPH_PNG
        self.call_dot_cmd   = GEN_GRAPH_DOT_CMD
        
    def title(self, words):
        words = words.replace("_", " ")
        words = words.title()
        return words    
        
    def show_info(self):
        print ""
        for key in vars(self):
            val = getattr(self, key)
            if not isinstance(val, dict):
                print "  %s:" % (self.title(key)) + " "*(20 - len(key)) + "%s" % (val)
        print ""
        

class Element:
    Keys = [
        "Id",
        "Api_Name",
        "Element_Name",
        "Element_Category", 
        "Failure_Mode", 
        "FM_Applicability", 
        "Comment_on_FM", 
        "Expected_Safety_Mechanism", 
        "Judgment", 
        "Rationale_on_SM", 
        "Remark"]
    def title(self, words):
        words = words.replace("_", " ")
        words = words.title()
        return words    
        
    def headLine(self):
        tilte_keys = map(lambda x: self.title(x), self.Keys)   
        return CSV_SEPERATOR.join(tilte_keys) + "\r\n"
        
    def createAttributes(self):
        for key in self.Keys:
            setattr(self, key, None)
            
    def __init__(self):
        global ID_START_INDEX
        #This will create attributes(properties) for this class
        #Then we could access thought variable by self.key
        #Example: self.Id, Self.Api_Name
        self.Keys = Element.Keys
        self.createAttributes()
        
        #Element ID will be automatically fill if ID_ENABLE is set
        if ID_ENABLE:
            self.Id = ID_PATTERN % (ID_START_INDEX)
            ID_START_INDEX += 1
    
    def set(self, key, value):
        setattr(self, key, value)
        
    def toDict(self):
        dict = {}
        for key in self.Keys:
            dict[key] = eval("self." + key)
        
        return dict
    
    def toCsvLine(self):
        line = []
        for key in self.Keys:
            val = eval("self." + key)
            if val is None:
                val = ""
            #fix new line in element name
            val = val.replace("\r", "").replace("\n", "")
            val = re.sub(r'\s+', ' ', val)
            line.append(val)
            
        return CSV_SEPERATOR.join(line) + "\r\n"

class ImportElement(Element):
    Keys = [
            "Object_Type",
            "Function_Name",
            "Element_Name",
            "Element_Category"
        ]
        
    def headLine(self):
        tilte_keys = map(lambda x: self.title(x), self.Keys)   
        return CSV_SEPERATOR.join(tilte_keys) + "\r\n"
        
    def __init__(self):
        self.Keys = ImportElement.Keys
        self.createAttributes()
        
class FunctionAttributes:
    
    Keys    = [
                "Name", 
                "FilePath", 
                "GlobalVars", 
                "MissingGlobalVar", 
                "GlobalPointers", 
                "LocalPointers", 
                "GlobalStruct",
                "GlobalArrays",
                "InputParams", 
                "ReturnType", 
                "Return", 
                "Loop", 
                "HwRegs", 
                "isPublic",
                "isInterrupt",
                "id", 
                "DisturbedAccessSequence",
                "CallCoverByCriticalSetions",
                "HasCriticalSection",
               ]
    
    def __init__(self):
        #This will create attributes(properties) for this class
        #Then we could access thought variable by self.key
        #Example: self.Name, Self.FilePath
        self.Keys = FunctionAttributes.Keys
        for key in self.Keys:
            setattr(self, key, None)
      
    def fromDict(self, dict):
        for key in self.Keys:
            setattr(self, key, dict[key])
            
        return self
        
    def display(self):
        print json.dumps(self.toDict(), indent=2)
        
    def toDict(self):
        dict = {}
        for key in self.Keys:
            dict[key] = eval("self." + key)
        
        return dict
    
    def get(self, attr_name):
        return getattr(self, attr_name)
        
    
    
