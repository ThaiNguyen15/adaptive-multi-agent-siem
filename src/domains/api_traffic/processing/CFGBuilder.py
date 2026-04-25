from clang import cindex
import os
from graphviz import Digraph

FILENAME = "example2.cpp"
ABS_FILE = os.path.abspath(FILENAME)

index = cindex.Index.create()
tu = index.parse(FILENAME, args=["-std=c++17", "-I."])


def is_from_main_file(node):
    try:
        return node.location.file and os.path.abspath(node.location.file.name) == ABS_FILE
    except:
        return False


# -------------------------
# CFG Builder
# -------------------------
class CFG:
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.counter = 0

    def new_node(self, label):
        node_id = f"N{self.counter}"
        self.counter += 1
        self.nodes.append((node_id, label))
        return node_id

    def add_edge(self, src, dst):
        self.edges.append((src, dst))


cfg = CFG()


def build_cfg(node, parent=None):
    if not is_from_main_file(node):
        for child in node.get_children():
            build_cfg(child, parent)
        return

    kind = node.kind.name
    name = node.spelling or node.displayname

    label = None

    if kind == "FUNCTION_DECL":
        label = f"FUNC {name}"

    elif kind == "IF_STMT":
        label = "IF"

    elif kind == "CALL_EXPR":
        label = f"CALL {name}"

    elif kind == "RETURN_STMT":
        label = "RETURN"

    elif kind == "BINARY_OPERATOR":
        label = "COND"

    if label:
        current = cfg.new_node(label)

        if parent:
            cfg.add_edge(parent, current)

        parent = current

    for child in node.get_children():
        build_cfg(child, parent)


build_cfg(tu.cursor)


# -------------------------
# Visualization
# -------------------------
dot = Digraph()

for node_id, label in cfg.nodes:
    dot.node(node_id, label)

for src, dst in cfg.edges:
    dot.edge(src, dst)

dot.render("cfg_output_2", format="png", cleanup=True)

print("CFG saved as cfg_output_2.png")