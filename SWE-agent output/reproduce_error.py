"""
reproduce_error.py
Minimal script to reproduce / inspect the view_range-parsing bug from
SWE-agent issue #1182 on SWE-agent v1.1.0.
"""

from sweagent.tools.parsing import XMLFunctionCallingParser
from sweagent.tools.commands import Command

# ----------------------------------------------------------------------
# 1.  Define a dummy command that matches what the model is *supposed*
#     to call.  (CommandArgument class isn’t available in v1.1.0, so we
#     pass a plain dict for each argument.)
# ----------------------------------------------------------------------

commands = [
    Command(
        name="View Code",
        docstring="View code in a specific range.",
        arguments=[
            {
                "name": "view_range",
                "type": "int, int",
                "description": "Start and end lines to view.",
                "required": True,
            }
        ],
    )
]

# ----------------------------------------------------------------------
# 2.  Craft a fake model response that *should* trigger the parser.
#     SWE-agent v1.1.0 expects the LLM output to arrive as a dict with a
#     "message" field, so we wrap the XML in that structure.
# ----------------------------------------------------------------------

xml_call = (
    "<function_call>"
    "<name>View Code</name>"
    "<arguments>"
    "<view_range>(5, 15)</view_range>"
    "</arguments>"
    "</function_call>"
)

model_response = {"message": xml_call}

# ----------------------------------------------------------------------
# 3.  Parse it and print the result (or the error).
# ----------------------------------------------------------------------

parser = XMLFunctionCallingParser()          # no args in v1.1.0

try:
    action = parser(model_response, commands)  # pass commands at call time
    print("✅ Parsed action:", action)
except Exception as e:
    print("❌ Error during parsing:", e)

