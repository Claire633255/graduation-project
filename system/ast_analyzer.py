import ast
import os

def parse_source_code(source_path):
    """
    解析Python源码为AST树
    :param source_path: 源码文件路径
    :return: AST树节点列表 / None（解析失败）
    """
    try:
        # 读取源码文件
        with open(source_path, "r", encoding="utf-8") as f:
            source_code = f.read()
        
        # 解析AST
        ast_tree = ast.parse(source_code)
        # 提取所有节点（简化版：遍历AST树）
        nodes = []
        for node in ast.walk(ast_tree):
            nodes.append(ast.dump(node))  # 转为字符串便于后续匹配
        return nodes
    
    except Exception as e:
        print(f"AST解析失败：{e}")
        return None

def parse_compressed_source(compress_path, temp_unzip_dir="temp_unzip"):
    """
    解析压缩包中的Python文件（批量模式）
    :param compress_path: 压缩包路径
    :param temp_unzip_dir: 临时解压目录
    :return: 字典{文件路径: AST节点列表}
    """
    import zipfile
    import tarfile
    import shutil

    # 清空临时解压目录
    if os.path.exists(temp_unzip_dir):
        shutil.rmtree(temp_unzip_dir)
    os.makedirs(temp_unzip_dir, exist_ok=True)

    # 解压压缩包
    try:
        if compress_path.endswith(".zip"):
            with zipfile.ZipFile(compress_path, "r") as zf:
                zf.extractall(temp_unzip_dir)
        elif compress_path.endswith((".tar.gz", ".tar")):
            with tarfile.open(compress_path, "r") as tf:
                tf.extractall(temp_unzip_dir)
        else:
            print("不支持的压缩包格式")
            return {}
    except Exception as e:
        print(f"解压失败：{e}")
        return {}

    # 遍历解压后的Python文件
    ast_results = {}
    for root, _, files in os.walk(temp_unzip_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                ast_nodes = parse_source_code(file_path)
                if ast_nodes:
                    ast_results[file_path] = ast_nodes
    
    return ast_results

if __name__ == "__main__":
    # 测试单文件解析
    # 使用当前脚本所在目录的相对路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(script_dir, "test.py")
    nodes = parse_source_code(test_file)
    if nodes:
        print(f"解析到{len(nodes)}个AST节点")