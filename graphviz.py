#!/usr/bin/python
import subprocess
from template import *
import json
from json import *
import sys
from fmea_utils import *    
sys.path.append("/cygdrive/e/trunghoang/graphviz-2.38/bin")

class DigGraph:
    START_GRAPH    = "digraph g {\n"
    END_GRAPH      = "}\n\n"
    def __init__(self, label=""):
        self.label = label
        self.nodes = []
        self.edges = []
        self.rankdir="LR"
        self.nodesep=0.5
        
    def add_node(self, node):
        self.nodes.append(node)
    
    def add_edge(self, edge):
        self.edges.append(edge)
        
    def to_dot(self):
        
        content = DigGraph.START_GRAPH
        
        for attr in vars(self):
            val = getattr(self, attr)
            if isinstance(val, list):
                for gattr in val:
                    content += gattr.to_dot()
                    
                content += "\n"
            else:
                content += '\t%s="%s"\n' % (attr, getattr(self, attr))
        
        content += DigGraph.END_GRAPH
        
        return content
    
class GraphvizAttrs:
    def __init__(self):
        #[penwidth=2.0]Adjusts the thickness of the edge line, Very useful for Paths
        self.penwidth = 2.0
        self.color = "black"
        self.name = ""
        self.shape = "box"
        
    def to_dot(self):
        attrs = []
        content = self.name + " ["
        for attr in vars(self):
            if attr != "name":
                val = getattr(self, attr)
                if val != "":
                    attrs.append("%s=%s" % (attr, str(val)))
                    
        content += ", ".join(attrs)
        content += "]"
        
        return "\t" + content + "\n"
        
    def fill_bottom(self, color):
        self.style="filled"
        self.gradientangle=90
        self.fillcolor =  '"%s;0.05:white"' % (color)
        
    def red_bottom(self):
        self.fill_bottom("red")
        
class Node(GraphvizAttrs):
    def __init__(self, name = ""):
        self.name  = name
        pass
    
        
class Edge(GraphvizAttrs):
    def __init__(self, name = ""):
        self.name = name


class GenCallGraph:

    def __init__(self):
        self.call_graph = DigGraph()
        
    def parse_call_db(self, call_json):
        full_cover_key = FULL_COVER_KEY
        call_cover_key = COVER_LIST_KEY
        db = {}
        with open(call_json) as dbf:
            db = json.load(dbf)
            
        for func, call_cover in db.items():
            node = Node(name=func)
            node.shape = "box"
            
            if call_cover[FULL_COVER_KEY]:
                node.color = "red"
            else:
                if call_cover["Has_Critical_Section"]:
                    node.red_bottom()
                    
            self.call_graph.add_node(node)   
            
            call_cover_list = call_cover[COVER_LIST_KEY]
            
            for item in call_cover_list:
                edge = Edge()
                edge.name = "%s->%s" % (item[0], func)
                if item[1] != "":
                    edge.color = "red"
                    
                self.call_graph.add_edge(edge)
                
            
            
    def gen_graph(self, dot_cmd = ""):
        with open(CALL_GRAPH_DOT, 'w') as dot:
            dot.write(self.call_graph.to_dot())
        if dot_cmd != "":
            info("Call dot to gen grap")
            subprocess.call(dot_cmd.split()) 
            
            
        
def test():
    from random import randint
    diggraph = DigGraph(label="Test Graphviz")
    
    for i in range(0, 10):
        node = Node("Node_%d" %(i))
        node.color = "red"
        node.penwidth = 4.0
        node.shape = "box"
        
        diggraph.add_node(node)
        
    for i in range(1, 30):
        n1 = 0
        n2 = 0
        while n1 == n2:
            n1 = randint(0,9)
            n2 = randint(0,9)
            
            
        edge = Edge("Node_%d -> Node_%d" %(n1, n2))
        edge.color="blue"
        edge.penwidth = 1.0
        edge.shape=""
        diggraph.add_edge(edge)
        
    print( diggraph.to_dot())
    
if __name__ == "__main__":
    test()