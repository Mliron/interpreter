"""
    Author: Matus Fabo (xfabom01)
    Date: 21.4.2021

    I highly recommend using code folding when reading the code.
"""
import argparse
from lxml import etree as et
import sys
import re
import time
#import traceback

XML = {
    "pro"    : ["language", "name", "description"],
    "ins"    : ["order", "opcode"],
    "arg"    : ["type"],
}
REGEX = {
    "var"     : r"^[GgLlTt][Ff]@[\w\-$&%*!?]+\s*$",
    "nil"     : r"^nil\s*$",
    "bool"    : r"^(true|false)\s*$",
    "string"  : r"^([^\s#\\\\]|[\\\\]\d\d\d)*\s*$",
    "int"     : r"^([\+\-]?\d+|0x[0-9a-fA-F]+|0b[01]+|0[0-7]+)\s*$",
    "label"   : r"^[\w\-$&%*!?]+\s*$",
    "type"    : r"^(int|string|bool)\s*$",
}
INSTRUCTION = {
   #Instruction            Parameter types
    "ADD"         : ["var",   "symb", "symb"    ],
    "SUB"         : ["var",   "symb", "symb"    ],
    "MUL"         : ["var",   "symb", "symb"    ],
    "IDIV"        : ["var",   "symb", "symb"    ],
    "LT"          : ["var",   "symb", "symb"    ],
    "GT"          : ["var",   "symb", "symb"    ],
    "EQ"          : ["var",   "symb", "symb"    ],
    "AND"         : ["var",   "symb", "symb"    ],
    "OR"          : ["var",   "symb", "symb"    ],
    "STRI2INT"    : ["var",   "symb", "symb"    ],
    "CONCAT"      : ["var",   "symb", "symb"    ],
    "GETCHAR"     : ["var",   "symb", "symb"    ],
    "SETCHAR"     : ["var",   "symb", "symb"    ],
    "MOVE"        : ["var",   "symb"            ],
    "NOT"         : ["var",   "symb"            ],
    "INT2CHAR"    : ["var",   "symb"            ],
    "STRLEN"      : ["var",   "symb"            ],
    "TYPE"        : ["var",   "symb"            ],
    "JUMPIFEQ"    : ["label", "symb", "symb"    ],
    "JUMPIFNEQ"   : ["label", "symb", "symb"    ],
    "CALL"        : ["label"                    ],
    "JUMP"        : ["label"                    ],
    "RETURN"      : [                           ],
    "LABEL"       : ["label"                    ],
    "DEFVAR"      : ["var"                      ],
    "POPS"        : ["var"                      ],
    "PUSHS"       : ["symb"                     ],
    "CREATEFRAME" : [                           ],
    "PUSHFRAME"   : [                           ],
    "POPFRAME"    : [                           ],
    "BREAK"       : [                           ],
    "DPRINT"      : ["symb"                     ],
    "EXIT"        : ["symb"                     ],
    "WRITE"       : ["symb"                     ],
    "READ"        : ["var",   "type"            ],
}
ERRCODE = {
    "OK"                    :  0,
    "BAD_PROGRAM_ARGS"      : 10,
    "INPUT_FILE"            : 11,
    "OUTPUT_FILE"           : 12,
    "XML_WELL_FORMED"       : 31,
    "XML_BAD_STRUCTURE"     : 32,
    "SEMANTICS"             : 52,
    "RUNTIME_BAD_TYPE"      : 53,
    "RUNTIME_NO_VAR"        : 54,
    "RUNTIME_NO_FRAME"      : 55,
    "RUNTIME_NO_VALUE"      : 56,
    "RUNTIME_BAD_VALUE"     : 57,
    "RUNTIME_BAD_STR_STUFF" : 58,
    "OTHER"                 : 99,
}
stdin_buffer = None

"""
    Handles program arguments

    Returns nothing
"""
def arg_parse():
    parser = argparse.ArgumentParser(description="IPPcode21 interpreter to execute IPPcode21 XML representation.")
    parser.add_argument("--source", nargs=1, metavar="file", help="XML representation of IPPcode21; Will be read from stdin if not present.")
    parser.add_argument("--input",  nargs=1, metavar="file", help="File with program input; Will be read from stdin if not present.")
    try:
        args = parser.parse_args()
    except SystemExit:
        exit(ERRCODE["BAD_PROGRAM_ARGS"])

    if args.input == args.source == None:
        print("usage: interpret.py [--help] [--source file] [--input file]", flush=True)
        print("You need to specify at least one of the arguments 'source' and 'input'.\nHow do you expect me to parse both from stdin?", flush=True)
        exit(ERRCODE["BAD_PROGRAM_ARGS"])

    return args

"""
    Preforms syntactic & lexical analysis and checks if given XML is well-formed
    file - String containing the XML file

    Returns etree structure containing converted XML file
"""
def xml_validate(file: str):
    def element_integrity(element, el_type, **kwargs):
        # Check name integrity
        if element.tag != el_type:
            exit(ERRCODE["XML_BAD_STRUCTURE"])

        # Check integrity of attributes
        for attr in element.keys():
            if not (attr in XML[el_type[0:3]]):
                exit(ERRCODE["XML_BAD_STRUCTURE"])

        # Check integrity of attribute values
        if el_type[0:3] == "pro":
            if element.get("language").lower() != "ippcode21":
                exit(ERRCODE["XML_BAD_STRUCTURE"])

        elif el_type[0:3] == "ins":
            if not (element.get("opcode").upper() in INSTRUCTION.keys()):
                exit(ERRCODE["XML_BAD_STRUCTURE"])
            if int(element.get("order")) < 1 or element.get("order") in tmp_dict:
                exit(ERRCODE["XML_BAD_STRUCTURE"])
            tmp_dict[element.get("order")] = "Yay, Im involved"
            if element.get("order") != str(kwargs["index"]):
                element.attrib["order"] = str(kwargs["index"])

        elif el_type[0:3] == "arg":
            # Check lexical correctness
            data_type = element.get("type").lower()
            if not (data_type in REGEX.keys()):
                exit(ERRCODE["XML_BAD_STRUCTURE"])

            if data_type == "string" and element.text == None:
                element.text = ""
            elif re.match(REGEX[data_type], element.text) == None:
                exit(ERRCODE["XML_BAD_STRUCTURE"])

            # Check syntactic correctness
            if kwargs["param_type"] != "symb":
                if data_type != kwargs["param_type"]:
                    exit(ERRCODE["XML_BAD_STRUCTURE"])
            else:
                if not (data_type in ["var","int","string","bool","nil"]):
                    exit(ERRCODE["XML_BAD_STRUCTURE"])

    # Convert xml string into etree
    try:
        xml_tree = et.fromstring(file.encode())
    except et.XMLSyntaxError:
        exit(ERRCODE["XML_WELL_FORMED"])

    # Check integrity of IPPcode21 XML program
    try:
        tmp_dict = {}
        xml_tree[:] = sorted(xml_tree, key=lambda item: int(item.get("order")))
        element_integrity(xml_tree, "program")
        for ins_index, instr in enumerate(xml_tree):
            instr.attrib["opcode"] = instr.attrib["opcode"].upper()
            element_integrity(instr, "instruction", index=ins_index+1)
            if len(instr.getchildren()) != len(INSTRUCTION[instr.get("opcode")]):
                exit(ERRCODE["XML_BAD_STRUCTURE"])
            instr[:] = sorted(instr, key=lambda item: int(item.tag[-1]))
            for arg_index, arg in enumerate(instr):
                arg.attrib["type"] = arg.attrib["type"].lower()
                element_integrity(arg, f"arg{arg_index+1}", param_type=INSTRUCTION[instr.get("opcode")][arg_index])
    except (KeyError, ValueError, TypeError):
        exit(ERRCODE["XML_BAD_STRUCTURE"])

    return xml_tree

"""
    Prints runtime program information
    wrapped - Dictionary containing "global" resources

    Returns nothing
"""
def debug_print(wrapped: dict):
    def something_about_length(var: str, len_text_above: int, offset: int):
        for i in range(int((len_text_above/2)) - int((len(var)/2)) + offset):
            print(' ', end='', file=sys.stderr, flush=True)
        print(var, end='\r', file=sys.stderr, flush=True)
    def dict_print(frame: dict):
        longest_goddamn_string_in_thiese_variables = len(max(frame.keys(), key=len))
        for x in frame:
            for i in range(longest_goddamn_string_in_thiese_variables+5):
                print(' ', end='', file=sys.stderr, flush=True)
            if frame[x][0] == "string":
                print(f':  {[frame[x][0], frame[x][1].encode()]}', end='\r', file=sys.stderr, flush=True)
            else:
                print(f':  {frame[x]}', end='\r', file=sys.stderr, flush=True)
            print(f' | {x}', file=sys.stderr, flush=True)
        print(" +", end='', file=sys.stderr, flush=True)
        for ohno in range(longest_goddamn_string_in_thiese_variables+4):
            print('-', end='', file=sys.stderr, flush=True)
        print('', file=sys.stderr, flush=True)

    print("============================DEBUG=============================", file=sys.stderr, flush=True)
    print("Program counter:        Executed instructions:        Runtime:", file=sys.stderr, flush=True)
    something_about_length(f'{(time.time() - wrapped["elapsed_time"]):.2f}s', len("Runtime:"), 54)
    something_about_length(str(wrapped["executed_count"]), len("Executed instructions:"), 24)
    something_about_length(str(wrapped["program_counter"]), len("Program counter:"), 0)

    print('', file=sys.stderr, flush=True)
    if wrapped["global_frame"].keys() != {}.keys():
        print("Global frame:", file=sys.stderr, flush=True)
        dict_print(wrapped["global_frame"])
    else:
        print("Global frame:     Empty", file=sys.stderr, flush=True)

    if wrapped["frame"][0] != None:
        if wrapped["frame"][0].keys() != {}.keys():
            print("Temporary frame:", file=sys.stderr, flush=True)
            dict_print(wrapped["frame"][0])
        else:
            print("Temporary frame:  Empty", file=sys.stderr, flush=True)
    else:
        print("Temporary frame:  Not defined", file=sys.stderr, flush=True)

    if wrapped["frame"][1] != None:
        print("Local frames:", file=sys.stderr, flush=True)
        for why_am_i_doing_this in range(len(wrapped["frame"])-2):
            if wrapped["frame"][why_am_i_doing_this+1].keys() != {}.keys():
                dict_print(wrapped["frame"][why_am_i_doing_this+1])
            else:
                print(" | Empty\n +------", file=sys.stderr, flush=True)
    else:
        print("Local frames:     Not defined", file=sys.stderr, flush=True)
    print("============================DEBUG=============================", file=sys.stderr, flush=True)

"""
    Finds all labels and stores them in "global" label table
    root - etree structure containing root of the XML program tree
    wrapped - Dictionary of "global" variables
"""
def find_labels(root: et._Element, wrapped: dict):
    for ins in root:
        if ins.get("opcode").upper() == "LABEL":
            if not (ins[0].text in wrapped["label"]):
                wrapped["label"][ins[0].text] = int(ins.get("order"))-1
            else:
                exit(ERRCODE["SEMANTICS"])

"""
    Converts IPPcode21 escape sequences to a normal string
    line - String containing IPPcode21 escape characters

    Returns converted string
"""
def str_convert(line: str):
    if re.match(REGEX["string"], line) == None:
        exit(ERRCODE["RUNTIME_BAD_VALUE"])

    tmp = line.split('\\')
    for i in range(len(tmp)-1):
        tmp[i+1] = chr(int(tmp[i+1][:3]))+tmp[i+1][3:]

    return "".join(tmp)

"""
    Execute given program
    code - etree root element of XML program representation
    input_stream - File or stdin, depends on program arguments

    Returns nothing
"""
def execute(code: et._Element, input_stream):
    def var_defined(var: str):
        # Check if variable is defined
        frame_scope, name = var.split('@')
        frame_scope = frame_scope.upper()
        if frame_scope == "GF":
            if name in wrap["global_frame"].keys():
                return 1
        elif frame_scope == "LF":
            if frame_check()&2:
                if name in wrap["frame"][1].keys():
                    return 1
            else:
                return -2
        elif frame_scope == "TF":
            if frame_check()&1:
                if name in wrap["frame"][0].keys():
                    return 1
            else:
                return -2
        return -1
    def symbol_good(arg:  et._Element):
        # Check it symbol is variable
        if(arg.get("type").lower() == "var"):
            return var_defined(arg.text)
        else:
            return 1
    def label_defined(name: str):
        # Check if label is defined
        return name in wrap["label"].keys()
    def frame_check():
        # Check state of frames; GF is always defined
        state_flag = 0
        if wrap["frame"][0] != None:    # TF
            state_flag += 0b01
        if wrap["frame"][1] != None:    # LF
            state_flag += 0b10
        return state_flag
    def var_get(var: str):
        retval = var_defined(var)
        if retval == -1:
            exit(ERRCODE["RUNTIME_NO_VAR"])
        elif retval == -2:
            exit(ERRCODE["RUNTIME_NO_FRAME"])

        frame_scope, name = var.split('@')
        frame_scope = frame_scope.upper()
        if frame_scope == "GF":
            return wrap["global_frame"][name]
        elif frame_scope == "LF":
            return wrap["frame"][1][name]
        elif frame_scope == "TF":
            return wrap["frame"][0][name]
        else:
            exit("var_get()")
    def var_set(var: str, val: list):
        retval = var_defined(var)
        if retval == -1:
            exit(ERRCODE["RUNTIME_NO_VAR"])
        elif retval == -2:
            exit(ERRCODE["RUNTIME_NO_FRAME"])

        frame_scope, name = var.split('@')
        frame_scope = frame_scope.upper()
        if frame_scope == "GF":
            wrap["global_frame"][name] = val
        elif frame_scope == "LF":
            wrap["frame"][1][name] = val
        elif frame_scope == "TF":
            wrap["frame"][0][name] = val
        else:
            exit("var_get()")
    def math_instr(instr: et._Element):
        # Check variable
        retval = var_defined(instr[0].text)
        if retval == -1:
            exit(ERRCODE["RUNTIME_NO_VAR"])
        elif retval == -2:
            exit(ERRCODE["RUNTIME_NO_FRAME"])

        # Check symbols
        if not symbol_good(instr[1]):
            exit(ERRCODE["SEMANTICS"])
        if len(instr) > 2 and not symbol_good(instr[2]):
            exit(ERRCODE["SEMANTICS"])
    def instr_dot_exe(instr: et._Element, wrapped: dict):
        def math_var_prep():
            var1 = [instr[1].get("type"), instr[1].text]
            if var1[0] == "string":
                var1[1] = str_convert(var1[1])
            elif var1[0] == "var":
                var1 = var_get(var1[1])
            var2 = [instr[2].get("type"), instr[2].text]
            if var2[0] == "string":
                var2[1] = str_convert(var2[1])
            elif var2[0] == "var":
                var2 = var_get(var2[1])
            return [var1, var2]
        def f_move():
            math_instr(instr)

            if instr[1].get("type") == "string":
                var_set(instr[0].text, ["string", str_convert(instr[1].text)])
            else:
                var = [instr[1].get("type"), instr[1].text]
                if var[0] == "var":
                    var = var_get(var[1])
                if var[0] == "nil":
                    var = ["nil", None]
                elif var[0] == "undef":
                    exit(ERRCODE["RUNTIME_NO_VALUE"])
                var_set(instr[0].text, var)
        def f_createframe():
            # No semantics check needed
            wrapped["frame"][0] = {}
        def f_pushframe():
            # Check if TF is defined
            if frame_check()&1 == 0:
                exit(ERRCODE["RUNTIME_NO_FRAME"])

            wrapped["frame"].insert(0, None)
        def f_popframe():
            # Check if frame stack has available frame
            if len(wrapped["frame"]) < 3 or wrapped["frame"][1] == None:
                exit(ERRCODE["RUNTIME_NO_FRAME"])

            del wrapped["frame"][0]
        def f_defvar():
            # Check if given variable is already defined
            if var_defined(instr[0].text) == 1:
                exit(ERRCODE["SEMANTICS"])

            var_scope, var_name = instr[0].text.split('@')
            var_scope = var_scope.upper()
            if var_scope == "GF":
                wrapped["global_frame"][var_name] = ["undef", None]
            elif var_scope == "LF":
                if not frame_check()&2:
                    exit(ERRCODE["RUNTIME_NO_FRAME"])
                wrapped["frame"][1][var_name] = ["undef", None]
            elif var_scope == "TF":
                if not frame_check()&1:
                    exit(ERRCODE["RUNTIME_NO_FRAME"])
                wrapped["frame"][0][var_name] = ["undef", None]
            else:
                exit("function f_defvar()", file=sys.stderr)
        def f_call():
            # Check if label is defined
            if not label_defined(instr[0].text):
                exit(ERRCODE["SEMANTICS"])

            wrapped["call_stack"].append(wrapped["program_counter"])
            wrapped["program_counter"] = wrapped["label"][instr[0].text]
        def f_return():
            # Call stack must not be empty
            if len(wrapped["call_stack"]) < 1:
                exit(ERRCODE["RUNTIME_NO_VALUE"])

            wrapped["program_counter"] = wrapped["call_stack"].pop()
        def f_pushs():
            # Symbol must be good
            retval = symbol_good(instr[0])
            if retval == -1:
                exit(ERRCODE["RUNTIME_NO_VAR"])
            elif retval == -2:
                exit(ERRCODE["RUNTIME_NO_FRAME"])

            pushing = [instr[0].get("type"), instr[0].text]
            if pushing[0] == "var":
                pushing = var_get(pushing[1])

            if pushing[0] == "string":
                wrapped["val_stack"].append(["string", str_convert(pushing[1])])
            elif pushing[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                wrapped["val_stack"].append(pushing)
        def f_pops():
            # Value stack must not be empty
            if len(wrapped["val_stack"]) < 1:
                exit(ERRCODE["RUNTIME_NO_VALUE"])

            var_set(instr[0].text, wrapped["val_stack"].pop())
        def f_add():
            math_instr(instr)
            var1, var2 = math_var_prep()

            if var1[0] == var2[0] == "int":
                var_set(instr[0].text, ["int", int(var1[1]) + int(var2[1])])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_sub():
            math_instr(instr)
            var1, var2 = math_var_prep()

            if var1[0] == var2[0] == "int":
                var_set(instr[0].text, ["int", int(var1[1]) - int(var2[1])])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_mul():
            math_instr(instr)
            var1, var2 = math_var_prep()

            if var1[0] == var2[0] == "int":
                var_set(instr[0].text, ["int", int(var1[1]) * int(var2[1])])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_idiv():
            math_instr(instr)
            var1, var2 = math_var_prep()

            if var1[0] == var2[0] == "int":
                if int(var2[1]) == 0:
                    exit(ERRCODE["RUNTIME_BAD_VALUE"])
                else:
                    var_set(instr[0].text, ["int", int(int(var1[1]) / int(var2[1]))])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_lt():
            math_instr(instr)
            var1, var2 = math_var_prep()
            if var1[0] == var2[0] == "int":
                var_set(instr[0].text, ["bool", "true" if int(var1[1]) < int(var2[1]) else "false"])
            elif var1[0] == var2[0] == "bool":
                var1[1] = 0 if var1[1] == "false" else 1
                var2[1] = 0 if var2[1] == "false" else 1
                var_set(instr[0].text, ["bool", "true" if var1[1] < var2[1] else "false"])
            elif var1[0] == var2[0] == "string":
                var_set(instr[0].text, ["bool", "true" if var1[1] < var2[1] else "false"])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_gt():
            var1, var2 = math_var_prep()
            if var1[0] == var2[0] == "int":
                var_set(instr[0].text, ["bool", "true" if int(var1[1]) > int(var2[1]) else "false"])
            elif var1[0] == var2[0] == "bool":
                var1[1] = 0 if var1[1] == "false" else 1
                var2[1] = 0 if var2[1] == "false" else 1
                var_set(instr[0].text, ["bool", "true" if var1[1] > var2[1] else "false"])
            elif var1[0] == var2[0] == "string":
                var_set(instr[0].text, ["bool", "true" if var1[1] > var2[1] else "false"])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_eq():
            var1, var2 = math_var_prep()
            if var1[0] == var2[0] == "int":
                var_set(instr[0].text, ["bool", "true" if int(var1[1]) == int(var2[1]) else "false"])
            elif var1[0] == var2[0] == "bool":
                var_set(instr[0].text, ["bool", "true" if var1[1] == var2[1] else "false"])
            elif var1[0] == var2[0] == "string":
                var_set(instr[0].text, ["bool", "true" if var1[1] == var2[1] else "false"])
            elif var1[0] == var2[0] == "nil":
                var_set(instr[0].text, ["bool", "true"])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            elif var1[0] == "nil" or var2[0] == "nil":
                var_set(instr[0].text, ["bool", "false"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_and():
            math_instr(instr)
            var1, var2 = math_var_prep()
            
            if var1[0] == var2[0] == "bool":
                var_set(instr[0].text, ["bool", "true" if var1[1] == var2[1] == "true" else "false"])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_or():
            math_instr(instr)
            var1, var2 = math_var_prep()
            
            if var1[0] == var2[0] == "bool":
                var_set(instr[0].text, ["bool", "true" if var1[1] == "true" or var2[1] == "true" else "false"])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_not():
            math_instr(instr)
            var1 = [instr[1].get("type"), instr[1].text]
            if var1[0] == "var":
                var1 = var_get(var1[1])
            
            if var1[0] == "bool":
                var_set(instr[0].text, ["bool", "true" if var1[1] == "false" else "false"])
            elif var1[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_int2char():
            math_instr(instr)
            var1 = [instr[1].get("type"), instr[1].text]
            if var1[0] == "var":
                var1 = var_get(var1[1])
            if var1[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            elif var1[0] != "int":
                exit(ERRCODE["RUNTIME_BAD_TYPE"])

            try:
                retval = ["string", f'{chr(int(var1[1]))}']
            except (TypeError, ValueError):
                exit(ERRCODE["RUNTIME_BAD_STR_STUFF"])
            var_set(instr[0].text, retval)
        def f_stri2int():
            math_instr(instr)
            var1, var2 = math_var_prep()
            if var1[0] == "string" and var2[0] == "int":
                if int(var2[1]) >= len(var1[1]) or int(var2[1]) < 0:
                    exit(ERRCODE["RUNTIME_BAD_STR_STUFF"])
                else:
                    retval = ["int", ord(str_convert(var1[1])[int(var2[1])])]
                    var_set(instr[0].text, retval)
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_read():
            global stdin_buffer
            if stdin_buffer != None:
                input_str = stdin_buffer
                stdin_buffer = None
            else:
                input_str = input_stream.readline()


            if len(input_str) != 0 and input_str[-1] == '\n':
                input_str = input_str[0:-1]

            if input_str == "":
                if instr[1].text == "string":
                    var_set(instr[0].text, ["string", ""])
                    return

            if instr[1].text == "int":
                try:
                    out_str = int(input_str)
                except ValueError:
                    out_str = ""
            elif instr[1].text == "bool":
                if input_str.lower() == "true":
                    out_str = "true"
                else:
                    out_str = "false"
            elif instr[1].text == "string":
                try:
                    out_str = str_convert(input_str)
                except SystemExit:
                    out_str = input_str
            else:
                out_str = ""

            if out_str != "":
                var_set(instr[0].text, [instr[1].text, out_str])
            else:
                stdin_buffer = input_str
                var_set(instr[0].text, ["nil", None])
        def f_write():
            var1 = [instr[0].get("type"), instr[0].text]
            if var1[0] == "var":
                var1 = var_get(var1[1])
                if var1[0] == "string":
                    print(var1[1], end='', flush=True)
                    return

            print_val = var1[1]

            if var1[0] == "nil":
                print_val = ""
            elif var1[0] == "string":
                print_val = str_convert(print_val)
            elif var1[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])

            print(print_val, end='', flush=True)
        def f_concat():
            math_instr(instr)
            var1, var2 = math_var_prep()

            if instr[1].get("type") != "var":
                var1[1] = str_convert(var1[1])
            if instr[2].get("type") != "var":
                var2[1] = str_convert(var2[1])

            if var1[0] == var2[0] == "string":
                var_set(instr[0].text, ["string", var1[1]+var2[1]])
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_strlen():
            math_instr(instr)
            var1 = [instr[1].get("type"), instr[1].text]
            if var1[0] == "var":
                var1 = var_get(var1[1])

            if var1[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            elif var1[0] != "string":
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
            else:
                var_set(instr[0].text, ["int", len(var1[1])])
        def f_getchar():
            math_instr(instr)
            var1, var2 = math_var_prep()
            if var1[0] == "string" and var2[0] == "int":
                if int(var2[1]) >= int(len(var1[1])) or int(var2[1]) < 0:
                    exit(ERRCODE["RUNTIME_BAD_STR_STUFF"])
                else:
                    retval = ["string", str(var1[1][int(var2[1])])]
                    var_set(instr[0].text, retval)
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_setchar():
            math_instr(instr)
            var0 = var_get(instr[0].text)
            var1, var2 = math_var_prep()
            if var0[0] == "string" and var1[0] == "int" and var2[0] == "string":
                if int(var1[1]) >= len(var0[1]) or len(var2[1]) == 0 or int(var1[1]) < 0:
                    exit(ERRCODE["RUNTIME_BAD_STR_STUFF"])
                else:
                    i_give_up = list(var0[1])
                    i_give_up[int(var1[1])] = str_convert(var2[1][0])
                    retval = ["string", "".join(i_give_up)]
                    var_set(instr[0].text, retval)
            elif var0[0] == "undef" or var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_type():
            math_instr(instr)
            var1 = [instr[1].get("type"), instr[1].text]
            if var1[0] == "var":
                var1 = var_get(instr[1].text)

            if var1[0] == "undef":
                var_set(instr[0].text, ["string", ""])
            elif var1[0] == "nil":
                var_set(instr[0].text, ["string", "nil"])
            else:
                var_set(instr[0].text, ["string", str(var1[0])])
        def f_label():
            # Labeling is done in preprocessing
            pass
        def f_jump():
            # Label has to be defined
            if not label_defined(instr[0].text):
                exit(ERRCODE["SEMANTICS"])

            wrapped["program_counter"] = wrapped["label"][instr[0].text]
        def f_jumpifeq():
            #Label has to be defined
            if not label_defined(instr[0].text):
                exit(ERRCODE["SEMANTICS"])

            # Symbols must be valid
            retval1 = symbol_good(instr[0])
            retval2 = symbol_good(instr[1])
            if retval1 == -1 or retval2 == -1:
                exit(ERRCODE["RUNTIME_NO_VAR"])
            if retval1 == -2 or retval2 == -2:
                exit(ERRCODE["RUNTIME_NO_FRAME"])

            var1, var2 = math_var_prep()
            if var1[0] == var2[0]:
                if var1[0] == "int":
                    var1[1] = int(var1[1])
                    var2[1] = int(var2[1])

                if var1[1] == var2[1]:
                    wrapped["program_counter"] = wrapped["label"][instr[0].text]
            elif var1[0] == "nil" or var2[0] == "nil":
                pass
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_jumpifneq():
            #Label has to be defined
            if not label_defined(instr[0].text):
                exit(ERRCODE["SEMANTICS"])

            # Symbols must be valid
            retval1 = symbol_good(instr[0])
            retval2 = symbol_good(instr[1])
            if retval1 == -1 or retval2 == -1:
                exit(ERRCODE["RUNTIME_NO_VAR"])
            if retval1 == -2 or retval2 == -2:
                exit(ERRCODE["RUNTIME_NO_FRAME"])

            var1, var2 = math_var_prep()
            if var1[0] == var2[0]:
                if var1[0] == "int":
                    var1[1] = int(var1[1])
                    var2[1] = int(var2[1])

                if var1[1] != var2[1]:
                    wrapped["program_counter"] = wrapped["label"][instr[0].text]
            elif var1[0] == "nil" or var2[0] == "nil":
                wrapped["program_counter"] = wrapped["label"][instr[0].text]
            elif var1[0] == "undef" or var2[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            else:
                exit(ERRCODE["RUNTIME_BAD_TYPE"])
        def f_exit():
            # Symbol must be defined
            retval = symbol_good(instr[0])
            if retval == -1:
                exit(ERRCODE["RUNTIME_NO_VAR"])
            if retval == -2:
                exit(ERRCODE["RUNTIME_NO_FRAME"])
            elif retval != 1:
                exit(ERRCODE["SEMANTICS"])

            exit_val = [instr[0].get("type"), instr[0].text]
            if exit_val[0] == "var":
                exit_val = var_get(exit_val[1])

            if exit_val[0] == "undef":
                exit(ERRCODE["RUNTIME_NO_VALUE"])
            elif exit_val[0] != "int":
                exit(ERRCODE["RUNTIME_BAD_TYPE"])

            if int(exit_val[1]) >= 0 and int(exit_val[1]) <= 49:
                exit(int(exit_val[1]))
            else:
                exit(ERRCODE["RUNTIME_BAD_VALUE"])
        def f_dprint():
            # Symbol must be defined
            if symbol_good(instr[0]) != 1:
                exit(ERRCODE["SEMANTICS"])

            print_val = [instr[0].get("type"), instr[0].text]
            if print_val[0] == "var":
                print_val = var_get(print_val[1])

            print(print_val[1], file=sys.stderr, flush=True)
        def f_break():
            # All semantics are dealt with in the function
            debug_print(wrapped, flush=True)
            return

        # State machine substitution
        eval(f'f_{instr.get("opcode").lower()}()')
        return

    if(len(code[:]) == 0):
        exit(0)

    # Create resources
    wrap = {
        "global_frame"     :    {},            # Frame dictionary => 'var_name : [var_type, var_value]'
        "frame"            :    [None, None],  # List of frame dictionaries
        "label"            :    {},
        "call_stack"       :    [],
        "val_stack"        :    [],
        "program_counter"  :    0,
        "executed_count"   :    0,
        "elapsed_time"     :    time.time()
    }
    find_labels(code, wrap)

    # Loop through each instruction
    last_index = int(code[-1].get("order"))
    while wrap["program_counter"] < last_index:
        # Execute instruction
        instr_dot_exe(code[wrap["program_counter"]], wrap)
        
        # Increase program counter
        if not (code[wrap["program_counter"]].get("opcode") in ["LABEL", "DPRINT", "BREAK"]):
            wrap["executed_count"] += 1
        wrap["program_counter"] += 1


def main():
    def get_file(file):
        try:
            gotten = open(file[0], "r")
        except TypeError:
            gotten = sys.stdin
        except FileNotFoundError:
            print(f"File '{file}' does not exist!", file=sys.stderr, flush=True)
            exit(ERRCODE["INPUT_FILE"])
        return gotten

    args = arg_parse()
    source_file = get_file(args.source)
    input_file = get_file(args.input)

    source_code = xml_validate(source_file.read())

    execute(source_code, input_file)

    source_file.close()
    input_file.close()

if __name__ == '__main__':
    main()


"""
    DEBUG lines that I didn't want to delete

    try:
        main()
    except SystemExit as e:
        traceback.print_exc()
        exit(int(str(e)))

        if len(code[wrap["program_counter"]].get("opcode")) < 8:
            print(f'{code[wrap["program_counter"]].get("opcode")}\t\t{wrap["program_counter"]}\t{wrap["executed_count"]}\t{wrap["global_frame"]}', flush=True, file=sys.stderr)
        else:
            print(f'{code[wrap["program_counter"]].get("opcode")}\t{wrap["program_counter"]}\t{wrap["executed_count"]}\t{wrap["global_frame"]}', flush=True, file=sys.stderr)
"""