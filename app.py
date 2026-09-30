#!/usr/bin/env python3
"""Safely patch proc_identity() in an existing Streamlit app.py.

Usage: python fix_pid.py /path/to/app.py
If no argument is given, patches app.py in the current directory.
"""
import ast
import os
import shutil
import sys
import tempfile
from pathlib import Path


def main():
    if len(sys.argv) > 2:
        raise SystemExit("用法: python fix_pid.py [app.py路径]")
    path = Path(sys.argv[1] if len(sys.argv) == 2 else "app.py")
    if not path.is_file():
        raise SystemExit(f"找不到文件: {path}")

    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SystemExit("暂不支持 UTF-8 BOM 文件；请先保存为 UTF-8 无 BOM。")
    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source, filename=str(path))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise SystemExit(f"源文件无法解析，未修改: {exc}")

    funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "proc_identity"]
    if len(funcs) != 1:
        raise SystemExit("未找到唯一的顶层 proc_identity()；未修改文件。")
    func = funcs[0]
    matches = []
    for node in func.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "pid"
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name) and node.value.func.id == "int"
                and len(node.value.args) == 1
                and isinstance(node.value.args[0], ast.Name)
                and node.value.args[0].id == "pid"
                and not node.value.keywords):
            matches.append(node)
    if len(matches) != 1:
        raise SystemExit("未找到唯一的函数顶层 pid = int(pid)；可能已修复或版本不同，未修改。")
    node = matches[0]
    lines = source.splitlines(keepends=True)
    if node.lineno != node.end_lineno:
        raise SystemExit("目标语句跨多行；未修改。")
    line = lines[node.lineno - 1]
    indent = line[:len(line) - len(line.lstrip(" \t"))]
    newline = "\r\n" if b"\r\n" in raw else "\n"
    replacement = [
        indent + "try:",
        indent + "    if isinstance(pid, bool):",
        indent + "        return False",
        indent + "    pid = int(pid)",
        indent + "    if pid <= 0:",
        indent + "        return False",
        indent + "except (TypeError, ValueError, OverflowError):",
        indent + "    return False",
    ]
    lines[node.lineno - 1] = newline.join(replacement) + newline
    updated = "".join(lines)
    try:
        compile(updated, str(path), "exec")
    except SyntaxError as exc:
        raise SystemExit(f"修复后的代码未通过语法检查，未修改: {exc}")

    backup = path.with_name(path.name + ".bak-pid-fix")
    if backup.exists():
        raise SystemExit(f"备份文件已存在: {backup}；未修改，以免覆盖备份。")
    shutil.copy2(path, backup)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent,
                                         prefix=path.name + ".", suffix=".tmp",
                                         delete=False) as out:
            temp_path = Path(out.name)
            out.write(updated.encode("utf-8"))
        shutil.copymode(path, temp_path)
        os.replace(temp_path, path)
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise
    print(f"已修复: {path}")
    print(f"原文件备份: {backup}")
    print("仅修复无效 PID 导致的面板崩溃；未修改代理出站配置。")


if __name__ == "__main__":
    main()
