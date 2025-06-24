import litellm
from langchain_core.prompts import PromptTemplate
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage, BaseMessage
from langchain_litellm import ChatLiteLLM
import os
from typing_extensions import Annotated, TypedDict
from typing import Dict, List, Set, Sequence, Tuple, Union
from langgraph.graph.message import add_messages
from langgraph.managed import IsLastStep, RemainingSteps
import env
import langchain.load
import subprocess
import glob
import json
import jazzer

from pydantic import BaseModel, Field

from litellm import completion

from langgraph.prebuilt import create_react_agent

from langchain.chat_models import init_chat_model
from langchain_core.tools import tool

permitted_dirs = [os.path.realpath(x) for x in
    [".",
    "/shared/java-targets/arrow-java/"]
]

WORKING_DIR = "/shared/java-targets/arrow-java/"

JAVA_INFO = None


def validate_path(path: str) -> str:
    resolved_path = os.path.realpath(path)
    for p in permitted_dirs:
        if path.startswith(p):
            return resolved_path
    print("Bad path {} -> {}".format(path, resolved_path))
    exit(1)

@tool(parse_docstring=True)
def ls_tool(directory: str) -> list[str]:
    """Lists the files in the requested directory in json format. Not recursive.

    Args:
        directory (str): The directory to list

    Returns:
        The list of files
    """

    print('ls({})'.format(directory))
    resolved_path = validate_path(WORKING_DIR + '/' + directory)
    return os.listdir(resolved_path)

@tool(parse_docstring=True)
def glob_tool(query: str) -> list[str]:
    """Returns the list of files specified by the glob query. Recursive.

    Args:
        query (str): The glob query

    Returns:
        The list of files
    """

    print('glob({})'.format(query))
    res = glob.glob(query, root_dir=WORKING_DIR, recursive=True)

    if len(res) > 256:
        raise Exception("Glob returned too many files. {} > 256".format(len(res)))

    return res


@tool(parse_docstring=True)
def grep_tool(pattern: str, recursive: bool, file: str, skip_binary: bool = True, line_numbers: bool = True, only_matching: bool = False):
    """Executes the provided grep query. pattern and file are escaped.

    Grep responses are limited to the first 1024 chraracters. If the response is truncated, it ends with <grep_truncated>

    Args:
        pattern: Basic regex pattern to pass to grep.
        recursive: Passes the -r flag to grep
        file: Single file or directory to search
        skip_binary: Passes the -I flag to grep
        line_numbers: Passes the -n flag to grep. Prints line numbers in the response.
        only_matching: Passes the -o flag to grep. Print only the matched (non-empty) parts of a matching line, with each such part on a separate output line.
    """

    validate_path(WORKING_DIR + '/' + file)

    # It likes to escape parentheses incorrectly
    # pattern = pattern.replace('''\\(''', '\(')

    grep_arg = ["grep"] + (["-r"] if recursive else []) + \
               (["-I"] if skip_binary else []) + \
               (["-n"] if line_numbers else []) + \
               (["-o"] if only_matching else []) + \
               ["-E", pattern, file]

    print(grep_arg)

    res = subprocess.run(grep_arg, capture_output=True, cwd=WORKING_DIR)

    res_txt = res.stdout.decode("utf-8") #[:1024]

    if res.returncode != 0:
        raise Exception(res.stderr.decode("utf-8"))

    if res_txt.count('\n') >= 128:
        raise Exception("Too many lines in grep output. Please try a more targeted query.")

    return res_txt

@tool(parse_docstring=True)
def read_file_tool(file: str, start_line: int, end_line: int):
    """Reads a file to a array of lines, using 1 indexing.

    Args:
        file: The file to read
        start_line: The line to start reading from
        end_line: The last line to read, exclusive. Maximum 100 lines.

    Returns:
        The contents of the file, formatted as such: {"name": "file_name", "content": "file content", "start": start_line, "end": end_line, "remaining_lines": remaining_lines}
    """

    print('read({}:{}:{})'.format(file, start_line, end_line))

    if start_line > end_line:
        raise Exception("start_line must be lower than end_line")

    if end_line - start_line > 100:
        raise Exception("Too many lines requested. {} > 100".format(end_line - start_line))

    resolved_path = validate_path(WORKING_DIR + '/' + file)
    #print(resolved_path)

    with open(resolved_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        lines_range = lines[start_line-1:end_line-1]
        return {
            'name': file,
            'content': ['{}: {}'.format(start_line + x, lines_range[x]) for x in range(len(lines_range))],
            'start': start_line,
            'end': end_line,
            'remaining_lines': max(len(lines) - end_line + 1, 0)
        }


def method_in_parent(sig: str):
    sig = sig.replace(' ', '')

    name, params_str = sig.split('(')
    child_class, methodname = name.rsplit('.', 1)
    params = params_str.split(',')

    for parent_class in JAVA_INFO.child_parent_mapping.get(child_class, []):
        test_name = f"{parent_class}.{methodname if methodname != '<init>' else parent_class.split('.')[-1]}({params_str}"
        print("Test", test_name)
        test_res = JAVA_INFO.fuzzy_map.get(test_name)
        if test_res is not None:
            return test_res

    return None


def fuzzy_method_lookup(name: str):
    # First try fully qualified name
    if name in JAVA_INFO.methods:
        return JAVA_INFO.methods[name]

    original_name = name

    name = name.replace(' ', '')

    if '(' in name:
        name, params_str = name.split('(', 1)
    else:
        params_str = None

    parts = name.split('.')
    if len(parts) >= 2 and parts[-1] == '<init>':
        parts[-1] = parts[-2]
    name = '.'.join(parts)

    simple_name = parts[-1]

    if params_str is not None:
        names_to_lookup = [f"{name}({params_str}", name, simple_name]
    else:
        names_to_lookup = [name, simple_name]

    # Then try fuzzy map
    for name2 in names_to_lookup:
        #print('name2', name2)
        if name2 in JAVA_INFO.fuzzy_map:
            method_list = JAVA_INFO.fuzzy_map[name2]
            if len(method_list) == 1:
                return method_list[0]
            else:
                raise Exception(f"Method lookup '{original_name}' was ambiguous. Try one of these: [{','.join(m.signature for m in method_list)}]")

    if len(parts) >= 2:
        method_name = parts[-1]
        child_name = '.'.join(parts[:-1])
        for parent_name in JAVA_INFO.child_parent_mapping.get(child_name, []):
            method_list = JAVA_INFO.fuzzy_map.get(f'{parent_name}.{method_name}', None)
            if method_list is not None:
                if len(method_list) == 1:
                    return method_list[0]
                else:
                    raise Exception(
                        f"Method lookup '{original_name}' was ambiguous. Try one of these: [{','.join(m.signature for m in method_list)}]")


    raise Exception(f"Method '{original_name}' not found. Perhaps it is not reachable by this harness?")


@tool(parse_docstring=True)
def read_method_tool(fully_qualified_name: str):
    """Reads the entirety of a Java method, specified by the fully qualified name and signature.

    Args:
        fully_qualified_name: Fully qualified name and signature of the method, ie. java.lang.String.format(String, Object[])

    Returns:
        The contents of the method, in the following format:
        {"content": "Signature and body of the method", "file": "Location this method was found"}
    """

    print(f"read_method({fully_qualified_name})")

    m = fuzzy_method_lookup(fully_qualified_name)

    if m.full_path is None:
        raise Exception(f"Source is not available for method '{fully_qualified_name}'")

    if any(x in fully_qualified_name for x in infos.exclusion_list):
        return {
            "content": "",
            "file": m.file,
            "notice": "You have already modified this method. You must choose somewhere else to insert your bug. For this reason it is hidden. However, you may still use the targets tool on it."
        }

    with open(m.full_path, mode='r') as fin:
        return {
            "content": fin.readlines()[m.start_line-1:m.end_line],
            "file": m.file
        }

@tool(parse_docstring=True)
def method_targets_tool(fully_qualified_name: str):
    """Returns the set of methods which may be called by this method, including virtual calls.

    Args:
        fully_qualified_name: Fully qualified name and signature of the method, ie. java.lang.String.format(String, Object[])

    Returns:
        The list of fully qualified names of methods
    """

    print(f"get_targets({fully_qualified_name})")

    m = fuzzy_method_lookup(fully_qualified_name)
    return JAVA_INFO.forward_map.get(m.signature, [])

@tool(parse_docstring=True)
def method_callers_tool(fully_qualified_name: str):
    """Returns the list of methods which may call this method.

    Args:
        fully_qualified_name: Fully qualified name of the method

    Returns:
        The list of fully qualified names of methods which call it.
    """

    print(f"method_callers({fully_qualified_name})")

    m = fuzzy_method_lookup(fully_qualified_name)
    return list(m.callers)


ALL_TOOLS = {
    #"ls_tool": ls_tool,
    #"glob_tool": glob_tool,
    #"grep_tool": grep_tool,
    #"read_file_tool": read_file_tool,
    'read_method_tool': read_method_tool,
    'method_targets_tool': method_targets_tool,
    'method_callers_tool': method_callers_tool
}

class JavaMethodInfo:
    def __init__(self):
        self.callers = set()

    name: str = None
    signature: str
    callers: Set[str]
    min_depth: int = 999
    fully_qualified_name: str
    file: str = None
    full_path: str = None
    start_line: int = 0
    end_line: int = 0


class AllJavaInfo:
    def __init__(self):
        self.methods = {}
        self.forward_map = {}
        self.fuzzy_map = {}

    methods: Dict[str, JavaMethodInfo]
    forward_map: Dict[str, List[str]]
    fuzzy_map: Dict[str, List[JavaMethodInfo]]
    fuzz_reachable: Dict[str, List[str]]
    exclusion_list: List[str]


def read_codeql_reachability(f: str, method_reachable: str, fuzz_reachable: str, exclusion_list: str) -> AllJavaInfo:
    def parse_loc(loc: str):
        if not loc.startswith('file://'):
            raise Exception(f"Location doesn't start with file:// '{loc}'")
        try:
            f, l0, c0, l1, c1 = loc.rsplit(':', 4)
        except ValueError:
            raise Exception(f"Error parsing location '{loc}'")
        return (f, int(l0), int(c0), int(l1), int(c1))


    infos = AllJavaInfo()

    # Need to do something about implicitly called parent constructors, which
    # seem to report multiple line locations

    with open(f, "r") as fin:
        j = json.load(fin)['#select']['tuples']
        for l in j:
            name, signature, simpleSignature, callerFqn, callerSignature, callerLocation, depth, fqn, file, startLine, endLine, numberOfLines, bodyLocation = l

            if name is None:
                raise Exception(f"Missing name")

            if file == '<none>':
                file = None

            if bodyLocation == '<none>':
                bodyLocation = None

            fullSignature = fqn + '(' + signature.split('(')[1]
            callerFull = callerFqn + '(' + callerSignature.split('(')[1]

            #print(fullSignature, callerFull)

            # Body Lines. We should use the minimum of this and the startLine, which is the signature
            if bodyLocation is not None:
                f, l0, _, l1, _ = parse_loc(bodyLocation)

            info = infos.methods.setdefault(fullSignature, JavaMethodInfo())
            is_new = info.name is None
            info.name = name
            info.signature = fullSignature
            info.callers.add(callerFull)
            info.min_depth = min(info.min_depth, depth)
            info.fully_qualified_name = fqn
            if info.file is None:
                info.file = file
            if bodyLocation is not None:
                info.full_path = f.removeprefix('file://')
                info.start_line = min(l0, startLine)
                info.end_line = l1

            forward_map = infos.forward_map.setdefault(callerFull, [])
            if fullSignature not in forward_map:
                forward_map.append(fullSignature)

            # We don't want to conflict with our own names! Also only do it the first time this info appears
            if is_new:
                simple_params_fqn_name = fqn + '(' + simpleSignature.split('(')[1]
                fuzzy_names = {name, signature, fullSignature, fqn, simpleSignature, simple_params_fqn_name}
                for n in fuzzy_names:
                    infos.fuzzy_map.setdefault(n, []).append(info)

    child_parent_mapping = infos.child_parent_mapping = {}

    with open(method_reachable, "r") as fin:
        j = json.load(fin)

        for child, parent in j['#select']['tuples']:
            child_parent_mapping.setdefault(child, []).append(parent)

    with open(fuzz_reachable, "r") as fin:
        j = json.load(fin)["#select"]["tuples"]
        infos.fuzz_reachable = {}

        for callee, caller in j:
            infos.fuzz_reachable.setdefault(callee, []).append(caller)

    with open(exclusion_list, "r") as fin:
        infos.exclusion_list = [x.strip() for x in fin.readlines() if len(x.strip()) > 0]

    return infos


def generate_cve(agent, jazzer_task, i):
    applicable_methods = jazzer_task['methods']
    chosen_method = applicable_methods[i % len(applicable_methods)]
    chosen_method_uses = infos.fuzz_reachable.get(chosen_method, [])

    harness_str = open('harnesses/FuzzerTika.java', "r").read()

    chosen_method_str = ''
    if len(chosen_method_uses) > 0:
        chosen_method_str = ('Here are some existing uses of the chosen method. '
                             'Not all of these may be currently reachable from the harness: ') + json.dumps(chosen_method_uses) + '.'

    log_i = 1
    while True:
        log_name = f'agent_log_{log_i}.json'
        if not os.path.exists(log_name):
            break
        log_i += 1

    for step in agent.stream(
        {"messages": [
            {"role": "user",
             "content": 'I am working on an AI CVE detection system. To test this system, I am intentionally inserting '
                        'bugs into software libraries to verify that the detection system works. '
                        'Bugs which merely trigger an exception (such as array out of bounds) are *not* valid because, '
                        'while the exception is unintended behavior, it does not pose a security threat. Bugs should be '
                        'difficult to find, such as but not limited to relying on complex state of the program, off-by-1 '
                        'errors, or relatively unknown parts of the Java API which have unexpected behavior (ie. the thread local class loader). ' +
                        jazzer_task['prompt'] +
                        'The applicable fuzzed method is: ' + applicable_methods[i % len(applicable_methods)] + '. '
                        'You are working in the Apache tika Java codebase. You have various tools at your disposal to discover information '
                        'about the codebase. You should explore throughly before deciding where to insert the vulnerability. '
                        'You must inject the vulnerability in org.apache.tika.parser. '
                        'You must inject it in a particular file/mime type parser, not a meta-parser. '
                        'There may already be security bugs in the codebase, you should ignore these and choose a new location. ' +
                        chosen_method_str +
                        'If you cannot find a location which already utilizes the fuzzed method, you should synthesize a new use of the method. '
                        'Remember that it should not be easy to trigger your bug, it should depend on multiple specific conditions. '
                        'However, it should be deterministic - the bug should appear on every run with a particular input. It must not depend on things the attacker '
                        'does not control, such as Random or the date. You may modify multiple methods. '
                        'The entrypoint from where the codebase is fuzzed is attached. ```' + harness_str + '```. You may not modify this harness. '
                        'Your should generate the new implementation of the modified methods. Your implementation must not reveal its true nature, '
                        'and should appear similar in style to the codebase. You must not reference things like "magic" or "inject", since they '
                        'appear irregular. You must not reference vulnerabilities or bugs, or add comments describing your changes (but do not delete existing comments!). '
                        'Your final output must be [{"method": "fully qualified name of the updated method", "content": "new content of the method"}, ...]'
             }
        ]},
        config={"recursion_limit": 250},
        stream_mode='values'
    ):
        print(step['messages'][-1].content)

        # Don't write if we didn't successfully  run
        if len(step['messages']) > 2:
            with open(log_name, 'w') as fout:
                fout.write(langchain.load.dumps(step))


class MyAgentState(BaseModel):
    """The state of the agent."""

    messages: Annotated[Sequence[BaseMessage], add_messages]

    remaining_steps: RemainingSteps = 250

if __name__ == '__main__':
    #model = init_chat_model("gemini-2.5-flash", model_provider="google_genai")
    #model = ChatLiteLLM(model="openai/gemini-2.0-flash", api_key=os.environ.get("LITELLM_KEY"), api_base=os.environ.get("AIXCC_LITELLM_HOSTNAME"))
    #model = ChatLiteLLM(model="openai/claude-3.5-haiku", api_key=os.environ.get("LITELLM_KEY"), api_base=os.environ.get("AIXCC_LITELLM_HOSTNAME"))
    #model = ChatLiteLLM(model="openai/oai-gpt-4.1", api_key=os.environ.get("LITELLM_KEY"), api_base=os.environ.get("AIXCC_LITELLM_HOSTNAME"))
    #model = ChatLiteLLM(model="openai/claude-4-opus", api_key=os.environ.get("LITELLM_KEY"), api_base=os.environ.get("AIXCC_LITELLM_HOSTNAME"))
    #model = ChatLiteLLM(model="openai/gemini-2.5-pro", api_key=os.environ.get("LITELLM_KEY"), api_base=os.environ.get("AIXCC_LITELLM_HOSTNAME"))
    model = ChatLiteLLM(model="azure/gpt-4.1")

    agent = create_react_agent(
        model=model,
        tools=list(ALL_TOOLS.values()),
        prompt="Answer user queries about the codebase. You should perform all queries within the current directory. "
               #"Use only the most efficient tool for each job. Use multiple tools at once. "
               "Since you are an LLM, you have limited memory. You must minimize the amount of data you request from tools. Use multiple tools at once to minimize multiple queries. "
               "It is very important that you only provide the final output without any additional comments or remarks.",
        #response_format=JavaMethod
        state_schema=MyAgentState
    )

    # seen_methods = set()
    # build_method_list(agent)

    prefix = 'tika'
    infos = read_codeql_reachability(f'codeql/{prefix}-harness.json',
                                     f'codeql/{prefix}-parents.json',
                                     f'codeql/{prefix}-fuzz-reachable.json',
                                     f'harnesses/{prefix}-modified')

    jazzer_task = jazzer.ALL_JAZZER_SANITIZERS['os_command_injection']

    JAVA_INFO = infos

    generate_cve(agent, jazzer_task, 2)


