# LATTE
Binary taint analysis engine combining LLM and program analysis

LATTE （latte.py） works as a GHIDRA plugin. Select "Decompiler Parameter ID" when loading the program.
The default output directory is "/home/user/Document/Turbine Output/ "

1. Firstly, LATTE （latte.py） is used to extract the function name for the analysis of ask_source_dest.py.

2. Then fill the analysis results into config.yaml for dangerous flow extraction.
3. Finally, use vulchat.py for vulnerability analysis of dangerous flows.

latte_bench.py is LATTE to perform batch analysis code.

analysis_gptout.py is used to analyze the output of GPT.

The test cases are in the data directory.
