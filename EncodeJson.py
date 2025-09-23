import json


def write_to_json(file_path, data):
    """将数据写入JSON文件"""
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)  # indent=4增加可读性
    print(f"数据已成功写入到 {file_path}")

def read_from_json(file_path):
    """从JSON文件读取数据"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"从 {file_path} 成功读取数据")
        return data
    except FileNotFoundError:
        print(f"错误：文件 {file_path} 不存在")
        return None