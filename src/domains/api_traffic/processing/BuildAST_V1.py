from clang import cindex

FILENAME = "example2.cpp"

index = cindex.Index.create()
tu = index.parse(FILENAME, args=["-std=c++17"])

def is_from_main_file(node):
    try:
        return node.location.file and node.location.file.name.endswith(FILENAME)
    except:
        return False

def build_ast(node, depth=0, lines=None):
    if lines is None:
        lines = []

    if is_from_main_file(node):
        lines.append("  " * depth + f"{node.kind.name} - {node.spelling}")

    for child in node.get_children():
        build_ast(child, depth + 1, lines)

    return lines


ast_lines = build_ast(tu.cursor)

with open("ast_clean2.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(ast_lines))

print("Clean AST saved to ast_clean2.txt")