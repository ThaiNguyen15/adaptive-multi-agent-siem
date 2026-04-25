from clang import cindex
import os
import json

FILENAME = "example2.cpp"
ABS_FILE = os.path.abspath(FILENAME)

# Optional: set libclang path if needed
# cindex.Config.set_library_file("C:/Program Files/LLVM/bin/libclang.dll")

# Create index
index = cindex.Index.create()

# Parse with arguments (IMPORTANT)
tu = index.parse(
    FILENAME,
    args=[
        "-std=c++17",
        "-I."
    ]
)

# -------------------------
# Diagnostics (VERY IMPORTANT)
# -------------------------
print("=== Diagnostics ===")
for diag in tu.diagnostics:
    print(diag)
print("===================")


# -------------------------
# File filter (ROBUST)
# -------------------------
def is_from_main_file(node):
    try:
        if node.location.file is None:
            return False
        return os.path.abspath(node.location.file.name) == ABS_FILE
    except:
        return False


# -------------------------
# AST builder
# -------------------------
def build_ast(node, depth=0, lines=None):
    if lines is None:
        lines = []

    if is_from_main_file(node):
        name = node.spelling or node.displayname
        lines.append("  " * depth + f"{node.kind.name} - {name}")

    for child in node.get_children():
        build_ast(child, depth + 1, lines)

    return lines


# -------------------------
# Semantic extraction (IMPROVED)
# -------------------------
def extract_semantic(node, results):
    name = node.spelling or node.displayname
    kind = node.kind.name

    # Only FILTER extraction, NOT traversal
    if is_from_main_file(node):

        if kind == "CALL_EXPR":
            results.append({
                "type": "call",
                "name": name,
                "line": node.location.line
            })

        elif kind == "VAR_DECL":
            results.append({
                "type": "variable",
                "name": name,
                "line": node.location.line
            })

        elif kind == "DECL_REF_EXPR":
            results.append({
                "type": "reference",
                "name": name,
                "line": node.location.line
            })

        elif kind == "IF_STMT":
            results.append({
                "type": "control",
                "name": "if",
                "line": node.location.line
            })

        elif kind == "RETURN_STMT":
            results.append({
                "type": "return",
                "line": node.location.line
            })

    # ALWAYS traverse children
    for child in node.get_children():
        extract_semantic(child, results)

# -------------------------
# Run AST
# -------------------------
ast_lines = build_ast(tu.cursor)

with open("ast_notclean.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(ast_lines))

print("Clean AST saved to ast_notclean.txt")


# -------------------------
# Run semantic extraction
# -------------------------
semantic = []
extract_semantic(tu.cursor, semantic)

with open("semantic-notclean.json", "w", encoding="utf-8") as f:
    json.dump(semantic, f, indent=2)

print("Semantic tokens saved to semantic-notclean.json")