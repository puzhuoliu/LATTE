from azure_chat import *
from Utils import *
import time
import random
import timeout_decorator
import json
import signal
import functools


dir="/home/user/Document/Turbine_Output/Potentially Vulnerable/CWE78_bad"

debug="/home/user/Document/debug.json"

record="/home/user/Document/record.json"

file_out="/home/user/Document/GPT_78_bad_t07/"
#note "/" in the end

Vul_check = {}


base=["Yes","highly likely"]


#
# @timeout_decorator.timeout(60)
def timeout(sec):
    """
    timeout decorator
    :param sec: function raise TimeoutError after ? seconds
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapped_func(*args, **kwargs):

            def _handle_timeout(signum, frame):
                err_msg = f'Function {func.__name__} timed out after {sec} seconds'
                raise TimeoutError(err_msg)

            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(sec)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wrapped_func
    return decorator

def random_surround_color(s):
    return random.choice(
        ["\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[1;34m",
         "\033[1;35m", "\033[1;36m", "\033[1;37m", "\033[1;38m"]
    ) + s + "\033[0m"

@timeout(300)
def prompt_conver(chatbot,file,file_name):
    print(f'\n{random_surround_color("analysis " + file_name)}')
    print(time.strftime("%Y-%m-%d %H:%M:%S"))
    chatbot.reset()
    time.sleep(5)
    question_list = load_file(file)
    prompt_len = len(question_list)
    prompt = question_list[0]

    if file_name not in Vul_check:
        Vul_check[file_name] = {}
        response = chatbot.ask(prompt)
        print(f'\n{random_surround_color("ChatGPT: ")}', end="")
        print(response)
        # response=create_new_conversation(chatbot, file_name, prompt)
        res.append(response)

    if prompt_len == 2:
        time.sleep(5)
        response = chatbot.ask(question_list[1])
        print(f'\n{random_surround_color("ChatGPT: ")}', end="")
        print(response)
        res.append(response)
        save_file(file_out, file.split("/")[-1].split(".")[0], res)
        for one in base:
            if one in response:
                add_file(record, file)
                break
    else:
        for prompt_num in range(1, prompt_len - 1):
            time.sleep(5)
            response = chatbot.ask(question_list[prompt_num])
            print(f'\n{random_surround_color("ChatGPT: ")}', end="")
            print(response)
            res.append(response)

        time.sleep(5)
        response = chatbot.ask(question_list[prompt_len - 1])
        print(f'\n{random_surround_color("ChatGPT: ")}', end="")
        print(response)
        res.append(response)
        save_file(file_out, file.split("/")[-1].split(".")[0], res)
        for one in base:
            if one in response:
                add_file(record, file)
                break

# if __name__ == '__main__':


chatbot = Chatbot(api_key="XXXXXX",)

exist_list=[]
exist_files=walkFile(file_out)
for file in exist_files:
    file_name=file.split("/")[-1].replace("-output","")
    exist_list.append(file_name)

files = walkFile(dir)
for file in files:
    file_name=file.split("/")[-1]
    if file_name in exist_list:
        print(file_name)
        continue
    res=[]
    try:
        prompt_conver(chatbot,file,file_name)
        print("\n Finish one")
    except:
        print("\n Timeout!!!!!!!")
        with open(debug, 'a+') as f:
            json.dump(file + "\n", f)
        f.close()

print("Finish all")

