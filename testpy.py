a = [('x', '1'), (2, 'x'), (5, 'x')]
val = 'x'

# 使用列表推导和 enumerate 找到第一个匹配项的索引
index = next(index for index, item in enumerate(a) if item[1] == val)

print(index)  # 输出：1