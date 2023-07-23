from Utils import *

dir="/home/user/Document/GPT_78_bad_t07"

files=walkFile(dir)

result_file="/home/user/Document/GPT_analysis/"+dir.split("/")[-1]

yes_list=[]
no_list=[]

for file in files:
    try:
        prompt_list = load_file(file)
        prompt = prompt_list[-1]
        if "Yes," in prompt or "Yes." in prompt or 'there is a potential vulnerability' in prompt:
        #if "Yes," in prompt or "Yes." in prompt:
            # if "maximum value" not in prompt and " Although the code checks" not in prompt:
            no_list.append(file.split("/")[-1])
            print(prompt)
            print(file + "!!!!!!!!!!!!!!!!!!!")
            print("NEXT\n")
    except:
        print(file+"!!!!!!!!!!!!!!!!!!!")
        print("NEXT\n")

with open(result_file, 'w') as f:
    for value in no_list:
        f.write(value)
        f.write("\n")
f.close()



