# 导入核心依赖
import ast
import os

# ===================== 1. 模拟配置文件 config.py 内容 =====================
# 直接写在代码里，无需单独创建文件，模拟规则文件根路径
class Config:
    RULE_ROOT_PATH = "./official_rules/"  # 规则文件根目录（模拟）
config = Config()

# ===================== 2. 模拟官方规则加载器 official_rule_loader.py =====================
# 实现你代码中导入的OfficialRuleLoader，模拟规则路径获取逻辑
class OfficialRuleLoader:
    def __init__(self):
        # 初始化6类漏洞对应的官方规则文件名（模拟真实场景的规则文件）
        self.vuln_rule_mapping = {
            "path_traversal": "path_traversal_rule.yaml",
            "command_injection": "command_injection_rule.yaml",
            "sql_injection": "sql_injection_rule.yaml",
            "xss": "xss_rule.yaml",
            "open_redirect": "open_redirect_rule.yaml",
            "code_injection": "code_injection_rule.yaml"
        }
        # 确保规则根目录存在（模拟创建，避免路径不存在报错）
        if not os.path.exists(config.RULE_ROOT_PATH):
            os.makedirs(config.RULE_ROOT_PATH)

    def get_rule_path(self, vuln_type):
        """根据漏洞类型获取规则文件完整路径"""
        # 从映射中获取规则文件名，不存在则返回None
        rule_filename = self.vuln_rule_mapping.get(vuln_type)
        if not rule_filename:
            return None
        # 拼接完整路径（根路径 + 规则文件名）
        full_rule_path = os.path.join(config.RULE_ROOT_PATH, rule_filename)
        return full_rule_path

# ===================== 3. 核心工具：AST解析提取Source/Sink节点 =====================
def extract_source_sink_nodes(code: str) -> dict:
    """
    解析Python代码的AST，提取Source（用户输入）和Sink（危险操作）节点
    :param code: 待检测的Python代码字符串
    :return: 漏洞特征字典 vuln_features（含source_nodes/sink_nodes）
    """
    source_nodes = []  # 存储Source节点字符串
    sink_nodes = []    # 存储Sink节点字符串

    # 定义：判断是否为Source节点（用户可控输入）
    def is_source(node):
        # 匹配场景1：Web输入 request.form.get/request.args.get/request.GET/request.POST
        if isinstance(node, ast.Call):  # 匹配函数调用（如xxx.get()）
            if hasattr(node.func, 'attr') and node.func.attr == 'get':
                if hasattr(node.func.value, 'attr'):
                    if node.func.value.attr in ['form', 'args']:
                        if hasattr(node.func.value.value, 'id') and node.func.value.value.id == 'request':
                            return True
        # 匹配场景2：控制台输入 input()/raw_input()
        if isinstance(node, ast.Call) and hasattr(node.func, 'id'):
            if node.func.id in ['input', 'raw_input']:
                return True
        # 匹配场景3：命令行参数 sys.argv
        if isinstance(node, ast.Attribute):
            if node.attr == 'argv' and hasattr(node.value, 'id') and node.value.id == 'sys':
                return True
        # 匹配场景4：直接获取request的GET/POST属性
        if isinstance(node, ast.Attribute):
            if node.attr in ['GET', 'POST'] and hasattr(node.value, 'id') and node.value.id == 'request':
                return True
        return False

    # 定义：判断是否为Sink节点（危险操作，覆盖6类漏洞的核心Sink）
    def is_sink(node):
        # 先处理函数调用类型的Sink（大部分危险操作是函数调用）
        if isinstance(node, ast.Call) and hasattr(node.func, 'id'):
            sink_funcs = [
                'open', 'os.system', 'eval', 'exec', 'compile', 'render_template',
                'redirect', 'HttpResponseRedirect'
            ]
            if node.func.id in sink_funcs:
                return True
        # 处理属性访问类型的Sink（如os.path.join、subprocess.run）
        if isinstance(node, ast.Attribute):
            # 路径遍历：os.path.join/os.makedirs/os.remove
            if node.attr in ['join', 'makedirs', 'remove']:
                if hasattr(node.value, 'attr') and node.value.attr == 'path' and hasattr(node.value.value, 'id') and node.value.value.id == 'os':
                    return True
            # 命令注入：subprocess.run/Popen
            if node.attr in ['run', 'Popen'] and hasattr(node.value, 'id') and node.value.id == 'subprocess':
                return True
            # SQL注入：cursor.execute
            if node.attr == 'execute' and hasattr(node.value, 'id') and node.value.id == 'cursor':
                return True
            # XSS：html/mark_safe
            if node.attr in ['html', 'mark_safe']:
                return True
            # 代码注入：pickle.loads
            if node.attr == 'loads' and hasattr(node.value, 'id') and node.value.id == 'pickle':
                return True
        # 数据库连接类Sink（sqlite3.connect/mysql.connector）
        if isinstance(node, ast.Call) and hasattr(node.func, 'id'):
            if node.func.id == 'connect' and hasattr(node.func, 'value') and node.func.value.id in ['sqlite3', 'mysql.connector']:
                return True
        return False

    # 核心：解析代码为AST并遍历节点
    try:
        tree = ast.parse(code)  # 把代码转成AST抽象语法树
        for node in ast.walk(tree):  # 遍历AST所有节点（深度优先）
            if is_source(node):
                # 把AST节点转成字符串，加入source_nodes
                source_nodes.append(ast.dump(node, compact=True))
            if is_sink(node):
                # 把AST节点转成字符串，加入sink_nodes
                sink_nodes.append(ast.dump(node, compact=True))
    except SyntaxError as e:
        print(f"❌ 代码语法错误，无法解析：{e}")
        return {"source_nodes": [], "sink_nodes": []}

    # 生成最终的漏洞特征字典
    vuln_features = {
        "source_nodes": source_nodes,
        "sink_nodes": sink_nodes
    }
    return vuln_features

# ===================== 4. 核心函数：漏洞规则匹配（原match_vuln_rule） =====================
def match_vuln_rule(vuln_features):
    """匹配漏洞特征到6类官方规则，返回规则信息"""
    # 1. 提取并拼接特征文本：Source+Sink节点合并，转小写避免大小写匹配问题
    feature_text = " ".join(
        vuln_features.get("source_nodes", []) +
        vuln_features.get("sink_nodes", [])
    ).lower()

    # 2. 6类漏洞的特征关键词映射（核心匹配规则）
    feature_vuln_mapping = {
        "path_traversal": ["open(", "os.path.join(", "read("],  # 路径遍历核心关键词
        "command_injection": ["os.system(", "subprocess.run(", "shell=True"],
        "sql_injection": ["cursor.execute(", "sqlite3.connect(", "mysql.connector"],
        "xss": ["render_template(", "Response(", "html(", "mark_safe("],
        "open_redirect": ["redirect(", "HttpResponseRedirect", "Location:"],
        "code_injection": ["eval(", "exec(", "compile(", "pickle.loads("]
    }

    # 3. 遍历映射，匹配漏洞类型（任意关键词匹配即判定）
    matched_vuln_type = None
    for vuln_type, keywords in feature_vuln_mapping.items():
        if any(keyword in feature_text for keyword in keywords):
            matched_vuln_type = vuln_type
            break

    # 未匹配到任何漏洞类型
    if not matched_vuln_type:
        print("❌ 未匹配到6类漏洞中的任何类型")
        return None

    # 4. 调用官方规则加载器，获取规则路径
    rule_loader = OfficialRuleLoader()
    rule_path = rule_loader.get_rule_path(matched_vuln_type)

    # 匹配成功，返回规则详细信息
    if rule_path:
        return {
            "rule_path": rule_path,
            "rule_name": os.path.basename(rule_path),
            "vuln_type": matched_vuln_type,
            "type": "built-in",  # 标记为内置官方规则
            "match_status": "success"  # 匹配状态
        }
    return {"match_status": "failed", "reason": "未找到对应规则文件"}

# ===================== 5. 测试用例：核心演示路径遍历，保留其他用例对比 =====================
if __name__ == "__main__":
    print("="*80)
    print("开始测试：AST提取 + 漏洞匹配 + 规则加载 全流程（核心演示：路径遍历漏洞）")
    print("="*80)

    # 测试用例1：核心演示 - 路径遍历漏洞（Web场景+控制台场景双示例，覆盖常见Source/Sink）
    test_code_path = """
# 场景1：Web场景（高危，用户URL参数输入直接拼接路径打开文件）
from flask import request
import os
file_name = request.args.get('file')  # Source：Web URL参数输入
file_path = os.path.join('./files/', file_name)  # Sink：路径拼接（路径遍历核心）
with open(file_path, 'r', encoding='utf-8') as f:  # Sink：文件打开（路径遍历核心）
    content = f.read()  # Sink：文件读取
    print(content)

# 场景2：控制台场景（用户输入直接指定文件路径）
# user_input_path = input("请输入要查看的文件路径：")
# with open(user_input_path, 'r') as f:
#     print(f.read())
    """
    print("\n【核心测试用例1：路径遍历漏洞（path_traversal）- Web高危场景】")
    features_path = extract_source_sink_nodes(test_code_path)
    # 可选：打印提取的Source/Sink节点，直观看到特征文本原材料
    print(f"👉 提取到Source节点：{features_path['source_nodes']}")
    print(f"👉 提取到Sink节点：{features_path['sink_nodes']}")
    result_path = match_vuln_rule(features_path)
    print(f"✅ 最终检测结果：{result_path}")

    # 测试用例2：对比 - XSS漏洞（Flask场景）
    test_code_xss = """
from flask import Flask, request, render_template
app = Flask(__name__)
@app.route('/hello')
def hello():
    username = request.form.get('username')
    return render_template('hello.html', name=username)
    """
    print("\n【对比测试用例2：XSS跨站脚本漏洞】")
    features_xss = extract_source_sink_nodes(test_code_xss)
    result_xss = match_vuln_rule(features_xss)
    print(f"检测结果：{result_xss}")

    # 测试用例3：对比 - 命令注入漏洞
    test_code_cmd = """
import os
user_input = input("请输入命令：")
os.system(f"echo {user_input}")
    """
    print("\n【对比测试用例3：命令注入漏洞】")
    features_cmd = extract_source_sink_nodes(test_code_cmd)
    result_cmd = match_vuln_rule(features_cmd)
    print(f"检测结果：{result_cmd}")

    # 测试用例4：对比 - 无漏洞安全代码
    test_code_safe = """
# 纯业务逻辑，无用户输入、无危险操作
def calc_sum(a, b):
    return a + b

if __name__ == "__main__":
    res = calc_sum(10, 20)
    print(f"计算结果：{res}")
    """
    print("\n【对比测试用例4：无漏洞安全代码】")
    features_safe = extract_source_sink_nodes(test_code_safe)
    result_safe = match_vuln_rule(features_safe)
    print(f"检测结果：{result_safe}")

    print("\n" + "="*80)
    print("全流程测试结束（核心路径遍历漏洞检测成功）")
    print("="*80)