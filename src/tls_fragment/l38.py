def merge_dict(dict1, dict2):
    # 创建一个新字典，先复制 dict1 的内容
    result = dict1.copy()
    # 遍历 dict2 中的键值对
    for key, value in dict2.items():
        # 若键不在 result 中，则添加该键值对
        if key not in result:
            result[key] = value
    return result