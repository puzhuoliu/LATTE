"""
Azure GPT-x APIs
=============

This module provides some official GPT API, which includes
1. Azure OpenAI ChatCompletion API
2. Azure OpenAI Completion API
3. Azure OpenAI Embedding API
"""
import os
import time
import json
from datetime import datetime
import openai
from Utils import *


dir="/home/user/Document/Turbine_Output/Decompile_result/CWE_190_bad"

file_out="/home/user/Document/dest_source/cwe190bad/"
file_out_content="/home/user/Document/content/cwe190bad/"

openai.api_type = "XXXXXX"
openai.api_base = "XXXXXXX"
openai.api_key = "XXXXXXX"
openai.api_version = os.getenv("AZURE_OPENAI_VERSION") or "2023-03-15-preview"
# Candidate version: "2023-03-15-preview" and "2022-12-01"

# Azure OpenAI ChatCompletion API
def aoai_ask(prompt, engine="gpt-4-32k", temperature=0):
    knowledge_cutoff = "2021-09-01"
    current_date = datetime.now().strftime("%Y-%m-%d")

    if isinstance(prompt, str):
        system_prompt= f"You are ChatGPT, a large language model trained by OpenAI. Answer as concisely as possible. Knowledge cutoff: {knowledge_cutoff} Current date: {current_date}"
        system_prompt = {"role":"system","content":system_prompt}
        new_prompt = {"role":"user","content":prompt}
        final_prompt = []
        final_prompt.append(system_prompt)
        final_prompt.append(new_prompt)
    elif isinstance(prompt, list):
        final_prompt = prompt
    else:
        raise TypeError("Expected a string as input") 

    try:
        response = openai.ChatCompletion.create(
        engine=engine,
        messages = final_prompt,
        temperature=temperature,
        max_tokens=2000,
        top_p=0.95,
        frequency_penalty=0,
        presence_penalty=0,
        stop=None)
    except openai.error.APIConnectionError:
        print("API Connection Error, retrying...")
        response = openai.ChatCompletion.create(
        engine=engine,
        messages = final_prompt,
        temperature=temperature,
        max_tokens=2000,
        top_p=0.95,
        frequency_penalty=0,
        presence_penalty=0,
        stop=None)
    except openai.error.RateLimitError:
        print("The server is currently overloaded. Sleep 1 mins and retry...")
        time.sleep(60)
        response = openai.ChatCompletion.create(
        engine=engine,
        messages = final_prompt,
        temperature=temperature,
        max_tokens=2000,
        top_p=0.95,
        frequency_penalty=0,
        presence_penalty=0,
        stop=None)
    except openai.error.APIError:
        print("Invalid response object from API, retrying...")
        time.sleep(60)
        response = openai.ChatCompletion.create(
        engine=engine,
        messages = final_prompt,
        temperature=temperature,
        max_tokens=2000,
        top_p=0.95,
        frequency_penalty=0,
        presence_penalty=0,
        stop=None)
        
    text = response["choices"][0]["message"]["content"]


    print(f"GPT ({engine}): ", [text])
    return text

# Azure OpenAI Completion
def aoai_embedding(input_str, engine="text-embedding-ada-002"):

    response = openai.Embedding.create(
        input= input_str,
        engine=engine
    )

    embeddings = response['data'][0]['embedding']
    return embeddings


# Azure OpenAI Completion
def aoai_completion(new_prompt, engine="text-davinci-003", temperature=0):
    response = openai.Completion.create(
    engine=engine,  # see the playgroud to find the engine name
    prompt=new_prompt,
    temperature=temperature,
    max_tokens=2040,
    top_p=0.5,
    frequency_penalty=0,
    presence_penalty=0,
    best_of=1,
    stop=None)

    text = response["choices"][0]["text"]
    print(f"GPT (f{engine}) ", [text])
    return text

if __name__ == "__main__":
    prompt_source = "Please use the function name to find the function that can directly receive external input or generate pseudo random number as the taint source in the taint analysis. Function names without semantic information are ignored. And output only in the form of [function name, external input corresponding parameters order or return value] without other description"
    prompt_sink = "For taint analysis, please use the function name to find the taint sink that may lead to vulnerabilities such as command hijacking, buffer overflow, format string, etc. Function names without semantic information are ignored. And output only in the form of [function name, parameter order corresponding to the vulnerability] without other description."
    prompt_content="Based on the provided content only, please analyze whether the function has variables that control the loop or participate in calculations that may cause integer overflow or division by zero errors. If the variable exists, further analyze whether there is a dependency relationship with function parameters or external inputs. If there is such a variable, please output it in the form of [function name, the variable name, loop or calculation] without additional description. Returns 'No' if no such variable exists."


    exist_list_name = []
    exist_list_content = []

    exist_files = walkFile(file_out)
    for file in exist_files:
        file_name = file.split("/")[-1].replace("-srdst", "")
        exist_list_name.append(file_name)

    exist_files = walkFile(file_out_content)
    for file in exist_files:
        file_name = file.split("/")[-1].replace("-content", "")
        exist_list_content.append(file_name)

    files = walkFile(dir)
    for file in files:
        file_name = file.split("/")[-1]
        if "function_name" in file_name:
            if file_name in exist_list_name:
                print(file_name)
                continue
            function = load_file(file)
            function_dict=json.loads(function)
            function_list=str(function_dict.keys())
            print("candidate function"+function_list)
            prompt_source_final=prompt_source+function_list
            try:
                source=aoai_ask(prompt_source_final)
                print("\n Finish source one")
            except:
                print(file_name+"\n Timeout!!!!!!!")
                continue
            time.sleep(5)
            prompt_sink_final = prompt_sink + function_list
            try:
                sink=aoai_ask(prompt_sink_final)
                print("\n Finish sink one")
            except:

                print(file_name+"\n Timeout!!!!!!!")
                continue
            output="Source: "+source+"; Sink: "+sink
            file_path = file_out + file_name.strip(".json") + "-srdst.json"
            with open(file_path, 'w') as f:
                json.dump(output, f)
            f.close()
            time.sleep(5)



        # if "function_content" in file_name:
        #     result_final=[]
        #     if file_name in exist_list_content:
        #         print(file_name)
        #         continue
        #     function = load_file(file)
        #     function_dict=json.loads(function)
        #     function_list=function_dict.keys()
        #     for key in function_list:
        #         text="\n"+str(key)+"\n"+function_dict[key]
        #         print("candidate content" + text)
        #         prompt_content_final=prompt_content+text
        #         result = aoai_ask(prompt_content_final)
        #         if result != "No":
        #             result_final.append(result)
        #         time.sleep(6)
        #     file_path = file_out_content + file_name.strip(".json") + "-content.json"
        #     with open(file_path, 'w') as f:
        #         json.dump(str(result_final), f)
        #     f.close()
        #     print("\n Finish content one")
        #     time.sleep(6)


    print("Finish all")

    #aoai_ask("Please use the function name to find the function that can directly receive external input as the taint source in the taint analysis. Function names without semantic information are ignored. And output in the form of <function name, external input corresponding parameters order>.__ctype_b_loc,htons,strchr,FUN_0010106e,__stack_chk_fail,wprintf,listen,printf,rand,srand,strlen,recv,bind,FUN_00100ac0,FUN_00100cc0,close,__cxa_finalize,__isoc99_swscanf,FUN_00100c80,__DT_INIT,memset,accept,FUN_00100d80,puts,exit,__isoc99_sscanf,system,iswxdigi,time,socket")
    # aoai_ask("How are you?", engine="gpt-4")
    # aoai_embedding("How are you?")
