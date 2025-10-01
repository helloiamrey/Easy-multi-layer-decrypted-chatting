actual_code="print('Hello, World!')"
msg="print('Hello, World!')"

res=True
if len(msg)==len(actual_code):
    res=True
    for i in range(len(msg)):
        res= res&(msg[i]==actual_code[i])
        #verify code

print(res)