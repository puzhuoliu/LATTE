#!/usr/bin/env python2
import os
import sys
import readline
import datetime

readline.set_completer_delims(' \t\n=')
readline.parse_and_bind("tab: complete")
result_dir="/home/user/Document/Turbine_Output/Potentially Vulnerable/CWE_190_symbol_good/"

def main():
    result=[]

    dir_path = os.path.dirname(os.path.realpath(__file__))
    ghidra_path = "/home/user/Documents/ghidra_10.2.2_PUBLIC_20221115/ghidra_10.2.2_PUBLIC/support/analyzeHeadless"

    if not os.path.isfile(dir_path + '/latte.py'):
        print("Please copy latte.py to the same directory as this script")
        sys.exit(1)
    if not os.path.isfile(dir_path + '/ghidra_analysis_options_prescript.py'):
        print("Please copy ghidra_analysis_options_prescript.py to the same directory as this script")
        sys.exit(1)
    
    while True:
        #program_to_analyze_directory = "/home/user/Documents/karonte_firmware"
	program_to_analyze_directory = "/home/user/Documents/juliet-test-suite-c-master/606/CWE606/bad"
        if program_to_analyze_directory[-1] != "/":
            program_to_analyze_directory+="/"
        if os.path.isdir(program_to_analyze_directory):
            break
        else:
            print("Invalid path. please enter a valid path.")
            sys.exit(1)
    for program in os.listdir(result_dir):
        pre=program.split("-")[0]
	middle=program.split("-")[1]
	result.append(pre+"-"+middle)

    for program in os.listdir(program_to_analyze_directory):
	if program in result:
	    print("Result existing\n")
	    pass
	else:
            print("++++++++++++++++++++++++++++\n")
            os.environ['PROGRAM_NAME'] = program
            os.system("sh {} {} temporaryProjectA -import {} -preScript {} -postScript {} -deleteProject".format(ghidra_path, program_to_analyze_directory, program_to_analyze_directory+'/'+program, dir_path + "/ghidra_analysis_options_prescript.py", dir_path + "/latte.py"))
            print("-------------Finish {}------------------\n".format(program))
            print("++++++++++++++++++++++++++++\n")
    print("-------------Finish all------------------\n")
if __name__ == "__main__":
    main()
