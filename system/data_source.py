import os
import subprocess
import sys
import re
import zipfile
import tarfile
import tempfile
import shutil

class PythonDataSource:
    def __init__(self, source_path):
        self.source_path = os.path.abspath(source_path)
        # 调整数据库路径：为每个压缩包生成独立的数据库目录
        self.base_db_path = os.path.join(os.getcwd(), "temp", "python_vuln_dbs")
        # 临时解压根目录
        self.base_extract_dir = tempfile.mkdtemp(prefix="python_vuln_batch_extract_")
        # 支持的压缩包后缀
        self.supported_archives = ('.zip', '.tar.gz', '.tgz', '.tar')

    def __del__(self):
        """对象销毁时清理临时解压目录"""
        if os.path.exists(self.base_extract_dir):
            try:
                shutil.rmtree(self.base_extract_dir)
                print(f"[🗑️] 清理批量解压临时目录：{self.base_extract_dir}")
            except Exception as e:
                print(f"[⚠️] 清理临时目录失败：{str(e)}")

    def _scan_archives_in_folder(self):
        """扫描目标文件夹下所有支持的压缩包文件，返回文件路径列表"""
        archive_files = []
        if not os.path.isdir(self.source_path):
            raise Exception(f"错误：{self.source_path} 不是有效的文件夹")
        
        print(f"[🔍] 开始扫描 {self.source_path} 下的压缩包文件...")
        for root, dirs, files in os.walk(self.source_path):
            for file in files:
                if file.lower().endswith(self.supported_archives):
                    archive_path = os.path.join(root, file)
                    archive_files.append(archive_path)
                    print(f"    发现压缩包：{archive_path}")
        
        if not archive_files:
            raise Exception(f"错误：在{self.source_path}中未找到任何支持的压缩包（{self.supported_archives}）")
        
        print(f"[✅] 共扫描到 {len(archive_files)} 个压缩包文件")
        return archive_files

    def _extract_archive(self, archive_path):
        """解压单个压缩包到独立的临时目录，返回解压后的根目录"""
        # 为每个压缩包创建独立的解压目录（避免文件名冲突）
        archive_name = os.path.splitext(os.path.basename(archive_path))[0]
        extract_dir = os.path.join(self.base_extract_dir, archive_name)
        os.makedirs(extract_dir, exist_ok=True)
        
        # 根据后缀选择解压方式
        if archive_path.lower().endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif archive_path.lower().endswith(('.tar.gz', '.tgz')):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_dir)
        elif archive_path.lower().endswith('.tar'):
            with tarfile.open(archive_path, 'r') as tar_ref:
                tar_ref.extractall(extract_dir)
        
        # 处理解压后单层文件夹的情况
        root_contents = os.listdir(extract_dir)
        if len(root_contents) == 1 and os.path.isdir(os.path.join(extract_dir, root_contents[0])):
            extract_root = os.path.join(extract_dir, root_contents[0])
        else:
            extract_root = extract_dir
        
        print(f"[✅] 压缩包解压完成：{archive_path} → {extract_root}")
        return extract_root

    def _check_python_files(self, check_path):
        """校验指定路径下是否有Python文件"""
        py_files = []
        for root, dirs, files in os.walk(check_path):
            for file in files:
                if file.endswith(".py"):
                    py_files.append(os.path.join(root, file))
        if not py_files:
            return False  # 不是Python项目，返回False
        print(f"[✅] 检测到Python项目，共找到{len(py_files)}个.py文件")
        return True

    def _generate_single_db(self, source_path, db_name):
        """为单个源路径生成CodeQL数据库"""
        # 生成独立的数据库路径
        db_path = os.path.join(self.base_db_path, db_name)
        
        # 删除旧数据库
        if os.path.exists(db_path):
            subprocess.run(
                f"rm -rf {db_path}" if sys.platform != "win32" else f"rmdir /s /q {db_path}",
                shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        
        # 生成数据库
        cmd = [
            "codeql", "database", "create",
            db_path,
            "--language", "python",
            "--source-root", source_path,
            "--overwrite"
        ]
        print(f"[⚙️] 生成CodeQL数据库：{' '.join(cmd)}")
        result = subprocess.run(
            cmd, shell=False, capture_output=True, text=True, encoding="utf-8"
        )
        if result.returncode != 0:
            raise Exception(f"数据库生成失败：{result.stderr}")
        print(f"[✅] CodeQL数据库生成完成：{db_path}")
        return db_path

    def batch_generate_codeql_dbs(self):
        """批量处理文件夹下的所有压缩包，生成对应的CodeQL数据库"""
        try:
            # 第一步：扫描目标文件夹下的所有压缩包
            archive_files = self._scan_archives_in_folder()
            
            # 第二步：确保数据库根目录存在
            os.makedirs(self.base_db_path, exist_ok=True)
            
            # 第三步：逐个处理压缩包
            success_dbs = []
            failed_archives = []
            
            for archive_file in archive_files:
                print(f"\n[📦] 开始处理压缩包：{archive_file}")
                try:
                    # 解压压缩包
                    extract_root = self._extract_archive(archive_file)
                    
                    # 检查是否是Python项目
                    if not self._check_python_files(extract_root):
                        print(f"[⚠️] 跳过：{archive_file} 不是Python项目（无.py文件）")
                        continue
                    
                    # 生成数据库（用压缩包名作为数据库名）
                    db_name = os.path.splitext(os.path.basename(archive_file))[0]
                    db_path = self._generate_single_db(extract_root, db_name)
                    
                    success_dbs.append({
                        "archive": archive_file,
                        "db_path": db_path
                    })
                except Exception as e:
                    print(f"[❌] 处理压缩包 {archive_file} 失败：{str(e)}")
                    failed_archives.append({
                        "archive": archive_file,
                        "error": str(e)
                    })
            
            # 第四步：输出批量处理结果
            print("\n" + "="*50)
            print(f"[📊] 批量处理结果汇总：")
            print(f"    总压缩包数：{len(archive_files)}")
            print(f"    成功生成数据库数：{len(success_dbs)}")
            print(f"    失败数：{len(failed_archives)}")
            
            if success_dbs:
                print(f"\n    成功列表：")
                for item in success_dbs:
                    print(f"      - {item['archive']} → {item['db_path']}")
            
            if failed_archives:
                print(f"\n    失败列表：")
                for item in failed_archives:
                    print(f"      - {item['archive']}：{item['error']}")
            
            return {
                "success": success_dbs,
                "failed": failed_archives
            }
        
        except Exception as e:
            print(f"[❌] 批量处理失败：{str(e)}")
            raise

if __name__ == "__main__":
    # 测试：传入包含多个压缩包的文件夹路径
    source = "E:/gra_pro/targets/python/CVE-2024-8412"  # 这个文件夹里有多个.zip/.tar.gz文件
    ds = PythonDataSource(source)
    ds.batch_generate_codeql_dbs()