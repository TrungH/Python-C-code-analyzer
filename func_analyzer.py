#!/usr/bin/python
import sys
import re, os
from template import *
from data_types import FunctionAttributes as FuncAttrs
from data_types import Configuration
from data_types import *
from fmea_utils import *
from json import *
import json
from pprint import pprint
import datetime
import traceback
USAGE = \
'''
* {}
  --------------------
        1. Split functions into seperated file
        2. Generate element for each type in SafetyAnalysis:
           Global variables
           Global pointers
           Global structure
           Input parameters(var/ptr)
           Loop
           Return
           Time execution
           Input Coherency
           Scheduling
           Hw Element
           Draw call graph with critical section cover information
        3. Ouput to .csv file.
    ------    
    Usage:
    ------
        0. Modify ID_PATTERN and ID_START_INDEX to fit your module id
        1. By default, go to your U:\external\X2x\modules\msn folder
        2. Then execute this script with no input
        3. {} -h/-help for help
    --------------    
    Advance usage:
    --------------
        Modify "template.py" for your need, it contains all configurable
        Recommend modify variables:
            - OUT_CSV
            - SOURCE_DIR
            - INC_DIR
            - OUTDIR
            - ID_PATTERN
            - ID_START_INDEX
        * Toggle DEBUG/INFO if you want to see debug information
    --------
    Example:
    --------
        $ cd /cygdrive/u/external/X2x/modules/spi
        $ /cygdrive/e/trunghoang/tool/func_analyzer.py
        
'''.format(APP_NAME, os.path.basename(sys.argv[0]))

class State:
    NONE = 0
    STRUCT_DETECT   = 1
    STRUCT_END      = 2
    STRUCT_START    = 3
    
    
class StructUnionParser:
    def __init__(self):
        self.state = State.NONE
        self.isStruct = False
        
    def process_file(self, file):
        db = []
        plenty_info("StructUnionParser")
        plenty_info("parsing file:" + file)
        
        with open(file) as header:
            for line in header:
                #Struct detected
                if STRUCT_DEF in line or UNION_DEF in line :
                    if STRUCT_DEF in line:
                        self.isStruct = True
                        debug("struct detected")
                        debug(line.strip())
                    if UNION_DEF in line:
                        self.isStruct = False
                        debug("union detected")
                        debug(line.strip())
                    self.state = State.STRUCT_DETECT
                    
                if self.state == State.STRUCT_DETECT:
                    if "{" in line:
                        self.state = State.STRUCT_START
                        if self.isStruct:
                            debug("struct started")
                        else:
                            debug("union started")
                        continue 
                        
                if self.state == State.STRUCT_START:
                    if "}" in line:
                        self.state = State.STRUCT_END
                        if self.isStruct:
                            debug("struct ended")
                        else:
                            debug("union ended")
                        continue
                    if STRUCT_DEF in line or UNION_DEF in line :
                        if STRUCT_DEF in line:
                            self.isStruct = True
                            debug("struct detected")
                            debug(line.strip())
                        if UNION_DEF in line:
                            self.isStruct = False
                            debug("union detected")
                            debug(line.strip())
                        self.state = State.STRUCT_DETECT
                        continue
                    if VOLATILE in line:
                        m = line.strip().split(" ")[-1]
                        m = re.findall(r'(\w+);', m)
                        if m:
                            db.append(m[0])
                            debug("Append: " + str(m[0]))
        return db
        
    def proccess(self, input_dir, out_json=None):
        plenty_info("  Parsing ...")
        db = []
        file_list = list_files_in_folder_recursive(input_dir)
        for f in file_list:
            db += self.process_file(f)
            
        debug(dumps(db, indent=2))
        if out_json is not None:
            with open(out_json, 'w') as output:
                plenty_info("Output: " + out_json)
                dump(db, output, indent=2)
            
        return db
        
    def info(self):
        print( "====================================================")
        print( "Struct/Union parser")
        print( "====================================================")
        
    
class HwRegGetter:
    def __init__(self):
        pass
        
    def reg_name(self, reg, line):
        hw_regs = []
        var_name_p = HW_REG_PATTERN + reg + ")"
        ms = re.findall(var_name_p, line)
        if ms:
            for m in ms:
                if "(" in m:
                    for mm in m.split("("):
                        if reg in mm:
                            m = mm
                    if ")" in m:
                        for mm in m.split(")"):
                            if reg in mm:
                                m = mm
                
                hw_regs.append(m)
        
        
        return hw_regs
        
        
        
    def get(self, volatile_db, content, func_name):
        plenty_info("HwRegGetter: paring " + func_name)
        hw_regs = []
        #with open(file) as input:
        #for line in content.splitlines():
        for reg in volatile_db:
            hw_regs += self.reg_name(reg, content)
            
                        
        hw_regs = list(set(hw_regs))
        plenty_info("hw_regs: " + json.dumps(hw_regs, indent=2))
        #by default it is <not present> if no hw regs
        if len(hw_regs) == 0:
            hw_regs = [NOT_PRESENT]
            
        hw_dict = {"var":hw_regs, "ptr":[]}
        
        return hw_dict
 

class GlobalVarGetter:
    def __init__(self, content, func_name):
        self.Content = content
        self.Msn = func_name.split("_")[0]
        self.func_name = func_name
        
    def varList(self):
        plenty_info("GlobalVarGetter: paring " + self.func_name)
        global_var_pattern = r'(' + self.Msn + "_G\w+)"
        global_match = re.findall(global_var_pattern, self.Content)
        if global_match:
            return global_match
        else: 
            return []

class FunctionContentWriter:
    def __init__(self, src_file, out_dir, func_name):
        root_name = "/".join(src_file.split("/")[:-1])
        self.File_path = os.path.join(os.getcwd(), out_dir, func_name + ".c")
        #Remove if exist
        remove_file(self.File_path)
        
    def write(self, content, global_vars):
        plenty_info( "FunctionContentWriter:Write file: " + self.File_path)
        global_vars_str = "Global Variables: \n"
        for gm in global_vars:
            global_vars_str += "\t" + gm + "\n"
            
        #build content with global var above.
        #concat with FUNC_SEP again as we filter it from above matching
        
        file_content = global_vars_str + FUNC_SEP + str(content)
        with open(self.File_path, 'w') as output:
            output.write(file_content)
            
        return self.File_path

class InputParamGetter:
    def __init__(self):
        pass
    
    def is_ptr(self, param):
        if P2CONST in param or P2VAR in param:
            return param
        else:
            return ""

    def is_var(self, param):
        if P2CONST in param or P2VAR in param or param == "void":
            return ""
        else:
            return param
            
            
    def get(self, file_path, func_name, content):
        plenty_info( "InputParamGetter process file:" + file_path)
        matches = re.findall(PARAM_INPUT_PATTERN, content, re.MULTILINE)
        input_params = []
        for m in matches:
            try:
               dict = {}
               filter_comment_pattern = r'(\/\*.*\*\/)'
               m = re.sub(filter_comment_pattern, "", m)
               if func_name in m:
                  params = m.split(func_name)[1].split("/*")[0].strip()
                  if params.startswith("("):
                    params = params[1:]
                    
                  if params.endswith(")"):
                    params = params[:-1]
                  
                  #replace p2const, p2var
                  params = re.sub(P2CONST_PATTERN, "P2CONST ", params)
                  params = re.sub(P2VAR_PATTERN, "P2VAR ", params).split(',')
                  params = map(lambda x: x.replace("\r\n", "").strip(), params)
                  params = map(lambda x: re.sub(r'\s+', ' ', x), params)
                  if len(params): 
                    debug(func_name + "input:" + json.dumps(params))
                    input_params =  params
                  
                  
            except:
                pass
            #filter to prt  and var
            ptr = filter(lambda x:self.is_ptr(x), input_params)
            var = filter(lambda x:self.is_var(x), input_params)
            
            #by default set 'em to <not present>
            if len(ptr) == 0:
                ptr = [NOT_PRESENT]
            if len(var) == 0:
                var = [NOT_PRESENT]
                
            input_params = {}
            if len(ptr) or len(var):
                input_params["ptr"] = ptr
                input_params["var"] = var
            else:
                input_params = None
                
            return input_params
            
class LoopGetter:
    def __init__(self):
        pass
    
    
    def beautize(self, str_input):
        str_input = str_input.replace("\n", "").replace("\r", "")
        str_input = re.sub(r'\s+', ' ', str_input)
        return str_input.strip()
        
    def get(self, file_path, content):
        plenty_info( "LoopGetter process file:" + file_path)
        loops = []
        
        #DO_WHILE_PATTERN    = r'}\s*(while\s*\([^;]*)'
        WHILE_PATTERN       = r'\s+(while\s*\([^{^;]*)'
        FOR_PATTERN         = r'\s+(for\s*\([^{]*)'   
        
        #matches = re.findall(DO_WHILE_PATTERN, content, re.MULTILINE)
        #if matches:
        #    for m in matches:
        #        loops.append("do{}" + self.beautize(m))
        
        matches = re.findall(WHILE_PATTERN, content, re.MULTILINE)    
        if matches:
            for m in matches:
                loops.append(self.beautize(m))
        
        matches = re.findall(FOR_PATTERN, content, re.MULTILINE)    
        if matches:
            for m in matches:
                loops.append(self.beautize(m))
        
        if len(loops) == 0:
            loops = [NOT_PRESENT]
        #else:
        #    ret = loops
            #ret = NEW_LINE.join(loops)
            #ret = '"' + ret + '"'
            
        loop_dict = {"var":loops, "ptr":[]}  
        debug("Loop" + json.dumps(loop_dict, indent=2))
        plenty_info("Number of loops: " + str(len(loops)))
        return loop_dict
        
class ReturnGetter:
    def __init__(self):
        pass
    
    def get(self, content, func):
        plenty_info("ReturnGetter: parsing " + func)
        return_type = "void"
        return_str = NOT_PRESENT
        for line in content.splitlines():
            line = line.strip()
            
            #get return type:
            if line.startswith("FUNC"):
                return_type = line.split(",")[0].replace("FUNC(", "")
            
            
            #get return variable name
            if line.startswith("return") and line.endswith(";"):
                m = re.findall(r'return\s*[\(]*(\w+)[\)]*\s*;', line)
                if m:
                    return_str = m[0].strip()
            

        return_dict = {"var":[return_str], "ptr":[]}
        return (return_type, return_dict)
                
#Global pointer, Local pointer, Global struct getter
#return (gp_dict, lp_dict, gst_dict)

class GLSAGetter:
    def __init__(self):
        pass
        
    def filter_special_chars(self, str):
        str = str.replace(',', "\,")
        return str
    
    def filter_ptr_var(self, input_array, type):
        dict = {}
        ptr = []
        var = []
        
        for el in input_array:
            el = el.replace(")", "").replace("(","").replace("--","").replace("++","")
            element = el
            element.replace("->", ".")
            if "." in element:
                element = element.split(".").pop()
                if element.startswith("p"):
                    ptr.append(el)
                else:
                    var.append(el)
            else:
                if type == "glp":
                    ptr.append(el)
                elif type == "gsa":
                    var.append(el)
            
        dict["ptr"] = ptr
        dict["var"] = var
        return dict
        
    def get(self, file, api_name, content):
        plenty_info( "GLSAGetter: " + "Processing" + file)
        lp = []
        gp = []
        gst = []
        gaa = []
        file_content = "".join(content)
        file_content = "FUNC" + file_content.split("FUNC")[1]
        m = re.findall(LP_PATTERN, file_content, re.MULTILINE)
        if m:
            
            lp = list(set(m))
            debug("Lp Found:")
            debug("\t" + "\n\t".join(list(set(m))))
        else :
            debug("No Lp pointer found\n")
        
        m = re.findall(GP_PATTERN, file_content, re.MULTILINE)
        if m:
            gp = list(set(m))
            debug("Gp Found:")
            debug("\t" + "\n\t".join(list(set(m))))
        else :
            debug("No Gp pointer found\n")
        
        m = re.findall(GST_PATTERN, file_content, re.MULTILINE)
        if m:
            gst = list(set(m))
            debug("Gst Found:")
            debug("\t" + "\n\t".join(gst))
        else :
            debug("No Gst pointer found\n")
            
        m = re.findall(GAA_PATTERN, file_content, re.MULTILINE)
        if m:
            debug(">>>" + json.dumps(m, indent=2))
            gaa = list(set(m))
            debug("Gaa Found:")
            debug("\t" + "\n\t".join(list(set(m))))
        else :
            debug("No Gaa pointer found\n")
            
        gp = self.filter_ptr_var(gp, "glp")
        lp = self.filter_ptr_var(lp, "glp")
        gst = self.filter_ptr_var(gst, "gsa")
        gaa = self.filter_ptr_var(gaa, "gsa")
        
        l = len(gp) + len(lp) + len(gst) + len(gaa)
        if l == 0:
            gp["ptr"] = [NOT_PRESENT]
            gp["var"] = [NOT_PRESENT]
        
        #for l in [gp, lp, gst, gaa]:
        #    if len(l["ptr"]): print json.dumps(l["ptr"], indent=2)
        #    if len(l["var"]): print json.dumps(l["var"], indent=2)
         
        return [gp, lp, gst, gaa]
        
class GetFuncType:
    def __init__(self):
        self.is_public = False
        self.is_interrupt = False
        
    def check_type(self, content):
        m = re.findall(PUBLIC_CODE, content)
        if m:
            self.is_public = True
        
    def check_interrupt(self, content):
        m = re.findall(INTERRUPT, content)
        if m:
            self.is_interrupt = True
           
    def get(self, func, file, content):
        plenty_info("GetFuncType: parsing " + func)
        #with open(file) as input:
        c = content
        self.check_interrupt(c)
        self.check_type(c)
        self.is_public = (self.is_public or self.is_interrupt)
        return (self.is_public, self.is_interrupt)


class FMEAGenerator:
    def __init__(self):
        pass
        
    def gen(self, config):
        self.json_file = config.json_file
        self.start_index = config.start_index;
        self.id_pattern = config.id_pattern
        self.csv_buffer = ""
        self.csv_import = ""
        
        #header for output.csv
        self.csv_buffer += Element().headLine()
        
        #output for out_template.csv
        #dummy to force Keys to reload 
        self.csv_import += ImportElement().headLine()
        
        with open(self.json_file) as dbf:
            db = json.load(dbf)
            #sorted keys list base on function id
            sorted_keys = sortdict(db, config.sort_key)
            for key in sorted_keys:
                #public api first
                func_attrs = db[key]
                if func_attrs['isPublic'] == True:
                    sorted_keys.remove(key)
                    self.process(func_attrs)
                
            #internal api    
            for key in sorted_keys:
                func_attrs = db[key]
                self.process(func_attrs)
                
        self.write_output(config)
        
    def write_output(self, config):
        with open(config.cvs_out, 'w') as csv_out:
            csv_out.write(self.csv_buffer)
            
        with open(config.csv_template, 'w') as csv_out:
            csv_out.write(self.csv_import)
    
    def gen_api_head_import_data(self, func_attr):
        e = ImportElement()
        if func_attr.isPublic:
            e.Object_Type = "ApiFunc"
        else:
            e.Object_Type = "IntFunc"
            
        e.Function_Name = func_attr.Name
        self.csv_import += e.toCsvLine()
        
    def gen_api_common_element(self, func_attr):
        if func_attr.isInterrupt:
            cat_name_fm = INTERRUPT_COMMON_CAT_NAME_FM
        else:
            cat_name_fm = API_COMMON_CAT_NAME_FM
            
        for key, value in cat_name_fm.iteritems():
            cat = key
            element_name = value[0]\
                            .replace("#API#", func_attr.Name)\
                            .replace("#Msn#", MODULE_NAME)
            fm = value[1]
            e = Element()
            
            if FUNCION_NAME_FOR_ELEMENT:
                e.Api_Name = func_attr.Name
                
            e.Element_Name = element_name
            e.Element_Category = cat
            e.Failure_Mode = fm
            
            #output to output.csv
            self.csv_buffer += e.toCsvLine()
            
            #Output to import template
            e = ImportElement()
            e.Object_Type = "Elem"
            e.Function_Name = ""
            e.Element_Name = element_name
            e.Element_Category = cat
            self.csv_import += e.toCsvLine()
            
    def process(self, func_attrs):
        plenty_info("Generating output for " + func_attrs["Name"])
        #convert dict to FuncAttrs instance, so we could access directly without key name
        func_attr = FuncAttrs().fromDict(func_attrs)
        e = Element()
        e.Api_Name = func_attr.Name
        e.Id = ""
        self.csv_buffer += e.toCsvLine()
        
        #gen head item for each API
        self.gen_api_head_import_data(func_attr)
        
        #generate element.
        for key, cats_fms in API_SEPECIFIC_CAT_FM.iteritems():
            debug("    key: " + key)
            vars = func_attrs[key]
            cats_dict = cats_fms["cat"]
            fms_dict = cats_fms["fm"]
            
            for ptr_var_key in ["ptr", "var"]:
                try:
                    fms = fms_dict[ptr_var_key]
                except:
                    fms = fms_dict
                    
                try:
                    cats = cats_dict[ptr_var_key]
                except:
                    cats = cats_dict
                    
                try:
                    var_list = vars[ptr_var_key]
                except:
                    var_list = vars
                    
                
                #conver cat and fm to list, so we could unify iterate method.
                if not isinstance(var_list, list):
                    var_list = [var_list]
                    
                if not isinstance(fms, list):
                    fms = [fms]
                    
                if not isinstance(cats, list):
                    cats = [cats]
                    
                debug("    cat:" + json.dumps(cats, indent=2))
                debug("    fm:" + json.dumps(fms, indent=2))
                
                self.gen_element(var_list, cats, fms, func_attr, key)
                
                
                #if vars doesn't a dict, then it single data without "ptr", "var" then we break to prevent duplicated line
                if not isinstance(vars, dict):
                    break
                
        self.gen_das_element(func_attr)    
            
        if func_attr.isPublic:
            self.gen_api_common_element(func_attr)
    
    def gen_das_element(self, func_attr):
        #abort das for variables in Msn_Init
        if func_attr.Name == MODULE_NAME + "_Init":
            return
        for data_type, das in func_attr.DisturbedAccessSequence.iteritems():
            for var_type in ["ptr", "var"]:
                for var_name, section_name in das[var_type]:
                    das_table = {}
                    
                    e = Element()
                    
                    if FUNCION_NAME_FOR_ELEMENT:
                        e.Api_Name = func_attr.Name
                        
                    e.Element_Name = var_name
                    e.Element_Category = API_SEPECIFIC_CAT_FM[data_type]["cat"][var_type]
                    
                    e.Failure_Mode = DISTURBED
                    
                    if section_name == "":
                        das_table = DAS_NOT_COVER
                    else:
                        das_table = DAS_COVER
                        
                    if "ConfigPtr" in var_name or \
                    (data_type == "LocalPointers" and "Config" in var_name):
                        das_table = DAS_NOT_APPLICABLE
                    
                    
                    if (not "." in var_name and not "->" in var_name and not "[" in var_name) and data_type == "GlobalPointers":
                        das_table = GP_ONLY_DAS_NOT_APPLICABLE
                        
                    for key, value in das_table.iteritems():
                        value = value.replace("#section#", section_name)
                        value = value.replace("#var_name#", var_name)
                        e.set(key, value)
                        
                    self.csv_buffer += e.toCsvLine()
        
        
    def gen_normal_element(self, var, func_attr, data_type, cat, fm):
        e = Element()
        func_name = func_attr.Name
        if FUNCION_NAME_FOR_ELEMENT:
            e.Api_Name = func_name
            
        e.Element_Name = var
        e.Element_Category = cat
        
        #FM is not needed for not present item
        if NOT_PRESENT != var:
            e.Failure_Mode = fm
        
        #write to cvs buffer
        self.csv_buffer += e.toCsvLine()
       
        
    def gen_imported_element(self, var, func_attr, data_type, cat, fm):
        func_name = func_attr.Name
        e = ImportElement()
        e.Object_Type = "Elem"
        e.Function_Name = func_name
        e.Element_Name = var
        e.Element_Category = cat
        
        #write cvs template buffer
        self.csv_import += e.toCsvLine()
        
        
    def gen_element(self, var_list, cats, fms, func_attr, data_type):
        func_name = func_attr.Name
        if var_list:
            for var in var_list:
                if var:
                    for cat in cats:
                        for fm in fms:
                            if fm != DISTURBED:
                                self.gen_normal_element(var, func_attr, data_type, cat, fm)
                                self.gen_imported_element(var, func_attr, data_type, cat, fm)

#Critical Section State
class CSState:
    NONE            = -1
    START_SECTION   =  0
    BOBY_SECTION    =  1
    END_SECTION     =  2
    
            

class CriticalSection:
    def __init__(self):
        pass

    def list(self, content):
        state = CSState.NONE
        sections = []
        sections_stack = []
        section = {}
        none_section = ""
        
        # split by func start so we could catch the outsider cretical section.
        content = re.split(FUNC_START, content)[1]
        lines = content.splitlines()
        for line in lines:
            #line = line.strip()
            m = re.findall(ENTER_CRITICAL_SECTION_PATTERN, line)
            if  m:
                if state == CSState.NONE:
                    section_name = m[0]
                    section_content = ""
                    state = CSState.START_SECTION
                    
                if state == CSState.BOBY_SECTION:
                    #push current section to list
                    sections_stack.append({section_name:section_content})
                    section_name = m[0]
                    section_content = ""
                    state = CSState.START_SECTION
                
                continue
            
            if state == CSState.START_SECTION and line.strip().startswith("#endif"):
                state = CSState.BOBY_SECTION
                continue
                
            if state == CSState.BOBY_SECTION:
                m = re.findall(EXIT_CRITICAL_SECTION_PATTERN, line)
                if m:
                    state = CSState.END_SECTION
                else:
                    section_content += line + "\n"
                continue
            
            if state == CSState.END_SECTION:
                #push finished section to output list
                sections.append({section_name:section_content})
                
                #pop current section from stack out to continue fill up content
                try:
                    current_sec = sections_stack.pop()
                    section_name = current_sec.keys()[0]
                    section_content = current_sec[section_name]
                except:
                    current_sec = None
                
                if current_sec is not None:
                    state = CSState.BOBY_SECTION
                else:
                    state = CSState.NONE
                continue
                
            none_section += line + "\n"
        
        return (sections, none_section)
        


class DisturbedAccessSequenceAnalyzer:
    def __init__(self):
        pass
    
    def in_section(self, section_list, var_name):
        for section in section_list:
            for name, content in section.iteritems():
                if var_name in content:
                    return [var_name, name]
            
        return None
        
    def in_none_section(self, none_section, var_name):
        if var_name in none_section:
            return [var_name, ""]
        else:
            return None
            
    def analyze(self, section_list, none_section, funcAttrs):
        debug("Build disturbed_dict for function" + funcAttrs.Name)
        disturbed_dict = {}

        for key, cat_fm in API_SEPECIFIC_CAT_FM.iteritems():
            dist_dict = {}
            ptr_dict = []
            var_dict = []
            fm = cat_fm["fm"]
            if DISTURBED in fm:
                data = funcAttrs.get(key)
                if isinstance(data, dict):
                    ptr_list = data["ptr"]
                    var_list = data["var"]
                    var = []
                    ptr = []
                    for var in ptr_list:
                        item = self.in_section(section_list, var)
                        if item:
                            ptr_dict.append(item)
                        item = self.in_none_section(none_section, var)
                        if item:
                            ptr_dict.append(item)
                        
                    for var in var_list:
                        item = self.in_section(section_list, var)
                        if item:
                            var_dict.append(item)
                        item = self.in_none_section(none_section, var)
                        if item:
                            var_dict.append(item)
                        
                    dist_dict["ptr"] = ptr_dict
                    dist_dict["var"] = var_dict
                    
                elif isinstance(data, list):
                    for var in data:
                        dist_dict[var] = []
                        item = self.in_section(section_list, var)
                        if item:
                            dist_dict[var].append(item)
                        item = self.in_none_section(none_section, var)
                        if item:
                            dist_dict[var].append(item)
                    
                disturbed_dict[key] = dist_dict
        
        return disturbed_dict            


class FunctionAnalyzer:
    # This is the entry point of the fmea analyzer, so we flush everything to get started
    def info(self):
        print("====================================================")
        print(APP_NAME )
        print("====================================================")
        print("Info: ")
        print("  Tool directory: {}".format(sys.argv[0]))
        print("  Working directory: " + os.getcwd())
        print("  Time: " + str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        
    def __init__(self, config):
        self.config = config
        self.fmea_db = config.db
        self.fmea_db.clear()
        self.fmea_json = config.json_file
        self.source_dir = config.source
        self.out_dir = config.output
        create_folder_if_not_exist(self.out_dir)    
        empty_folder(self.out_dir)
        remove_file(self.fmea_json)
        self.info()
        
    def analyze(self):
        print ("  Analyzing ... ")
        print ("  Preparing volatile database ..." )
        suParser = StructUnionParser()
        self.volatileDb = suParser.proccess(self.config.inc_dir, self.config.volatile_json)
        
        for f in list_files_in_folder_recursive(self.source_dir, ".c"):
            info("Analyzing file ... " + f)
            self.process(f)
            
        for func, func_attr in self.fmea_db.items():
            with open(func_attr["FilePath"]) as input:
                c = input.read()
                (section_list, none_section) = CriticalSection().list(c)
                CallCover().build(func, self.fmea_db.keys(), section_list, none_section, self.config.func_call_db)
                FullCoverByCriticallSection().build(func, c, self.config.func_call_db)
        
        with open(self.fmea_json, 'w') as fmea_json_out:
            json.dump(self.fmea_db, fmea_json_out, indent=2)

        with open(self.config.func_call_json, 'w') as func_call_json:
            json.dump(self.config.func_call_db, func_call_json, indent=2)
            
    def process(self, file):
        global FUNC_DB_ID, MODULE_NAME, FUNC_LIST
        
        outdir = self.out_dir
        
        
        content = ''
        with open(file) as input:
            content = input.read();
            
        func_list = content.split(FUNC_SEP)
        func_section_dict = {}
        
        for c in func_list:
            funcAttrs = FuncAttrs()
            m = re.findall(FUNC_PATTERN, c)
            if "Function Name" in c and m and "FUNC" in c:
                global_vars = []
                global_vars_str = "Global variables:\n"
                func_name = m[0]
                plenty_info("Analyzing function " + func_name)
                #Set function id to sort later, this is the order in .c file.
                funcAttrs.id = FUNC_DB_ID
                FUNC_DB_ID += 1
                
                if not func_name in FUNC_LIST:
                    info("Working on function:" + func_name)
                    FUNC_LIST.append(func_name)
                    if MODULE_NAME == "":
                        MODULE_NAME = func_name.split("_")[0]
                        
                        
                funcAttrs.Name = func_name
                
                #Filter duplicated var, and make sure it is not a function
                
                for gm in GlobalVarGetter("FUNC" + c.split("FUNC")[1], func_name).varList():
                    if not gm in global_vars and  (not gm in FUNC_LIST) :
                        global_vars.append(gm)
                        
                #set global var to func attributes
                funcAttrs.GlobalVars = global_vars
                
                #write to file, with Msn_Api.c
                func_writer = FunctionContentWriter(file, self.out_dir, func_name)
                funcAttrs.FilePath = func_writer.write(c, global_vars)
                
                #Get func type:
                (funcAttrs.isPublic, funcAttrs.isInterrupt) = GetFuncType().get(func_name, funcAttrs.FilePath, c)
                
                
                #get input params:
                if funcAttrs.isPublic:
                    funcAttrs.InputParams = InputParamGetter().get(funcAttrs.FilePath, func_name, c)
                
                #get loop
                funcAttrs.Loop = LoopGetter().get(funcAttrs.FilePath, c)
                
                #get Gp, Lp, Gst, Gaa
                glsa = GLSAGetter().get(funcAttrs.FilePath, func_name, c)
                funcAttrs.GlobalPointers    = glsa[0]
                funcAttrs.LocalPointers     = glsa[1]
                funcAttrs.GlobalStruct      = glsa[2]
                funcAttrs.GlobalArrays      = glsa[3]
                
                #Get hw reg list
                funcAttrs.HwRegs = HwRegGetter().get(self.volatileDb,c, func_name)
                
                #return get
                if funcAttrs.isPublic:
                    (funcAttrs.ReturnType, funcAttrs.Return) = ReturnGetter().get(c, func_name)
                else:
                    funcAttrs.Return = ""
                #
                (section_list, none_section) = CriticalSection().list(c)
                
                daa = DisturbedAccessSequenceAnalyzer();
                funcAttrs.DisturbedAccessSequence = daa.analyze(section_list, none_section, funcAttrs)
                
                #merge to db
                merge_dict_to_db(self.fmea_db, funcAttrs.toDict(), funcAttrs.Name)
                
                
class FullCoverByCriticallSection:
    def build(self, func, content, db):
        hit_func_body = False
        hit_critical_section = False
        quotes = 0
        hit_exit_critical_section = False
        
        full_cover_key = FULL_COVER_KEY
        
        if func in db.keys():
            call_dict = db[func]
        else:
            call_dict = {}
            
        content = re.split(FUNC_START, content)[1]
        
        lines = content.splitlines()
        
        #scan top to bottom, if see ENTER_CRITICAL_SECTION before any =.
        #(1)
        call_dict[full_cover_key] = False
        
        for line in lines:
            if "ENTER_CRITICAL_SECTION" in line:
                hit_critical_section = True
                break
                
            if "=" in line and line.strip().endswith(";"):
                hit_func_body = True
                break

        #if (1), then scan from bottom up, and see if hit EXIT after a }.                    
        if hit_critical_section and not hit_func_body:
            i = len(lines) - 1
            while i > 0:
                quotes += lines[i].count("}")
                if quotes > 1:
                    break
                if "EXIT_CRITICAL_SECTION" in lines[i]:
                    hit_exit_critical_section = True
                    break
                    
                i = i - 1   
        
            if quotes == 1 and hit_exit_critical_section:
                call_dict[full_cover_key] = True
                info("%s >>> full cover: True" % (func))
            
        
        if "ENTER_CRITICAL_SECTION" in content:
            call_dict["Has_Critical_Section"] = True
        else:
            call_dict["Has_Critical_Section"] = False
            
        db[func] = call_dict
            
        
class CallCover:         

    def __init__(self):
        pass
    def build(self, call_func, func_list, section_list, none_section, db):
        cover_list_key = COVER_LIST_KEY
        has_critical_section_key = "Has_Critical_Section"
        
        for func in func_list:
            if func != call_func:
                if func in db.keys():
                    call_dict = db[func]
                else:
                    call_dict = {}
                    
                if cover_list_key in call_dict.keys():
                    call_list = call_dict[cover_list_key]
                else:
                    call_list = []
                
                p1 = "%s " % (func)
                p2 = "%s(" % (func) 
                
                for section in section_list:
                    for section_name, section_content in section.iteritems():
                        if p1 in section_content or p2 in section_content:
                            item = [call_func, section_name]
                            call_list.append(item)
                
                if p1 in none_section or p2 in none_section:
                    item = [call_func, ""]
                    call_list.append(item)
                    
                call_dict[cover_list_key] = call_list
                db[func] = call_dict
        

def done_info(config):
    config.module_name  = MODULE_NAME
    config.total_api      = FUNC_DB_ID
    config.show_info()
    print("  Done!")
    print("  Wish you a lucky day ^.@ !")
    
def luck():
    print(LUCKY)
    
from graphviz import *

def main():
    global FUNC_DB_ID
    FUNC_DB_ID = 0
    config = Configuration()
    fanalyzer = FunctionAnalyzer(config)
    fanalyzer.analyze()
    fmeaGen = FMEAGenerator()
    fmeaGen.gen(config)
    gp = GenCallGraph()
    gp.parse_call_db(FUNC_CALL_JSON)
    gp.gen_graph(config.call_dot_cmd)
    
    done_info(config)
    luck()
        
    
def usage():
    print(USAGE)
    
    
if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1].lower().startswith('-h'):
        usage()
    else:
        main()
    


        