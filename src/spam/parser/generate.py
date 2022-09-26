from speedy_antlr_tool import generate
generate(
    py_parser_path="CPP14Parser.py",
    cpp_output_dir="cpp_src",
    entry_rule_names=["translationUnit"],
)