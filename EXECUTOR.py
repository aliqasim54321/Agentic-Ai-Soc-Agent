# Standard library
from datetime import timedelta
import json

# Third-party libraries
import pandas as pd
from colorama import Fore, Style
from openai import RateLimitError, OpenAIError

# Local modules
import PROMPT_MANAGEMENT

def hunt(openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model):
    """
    Runs the threat hunting flow:
    1. Formats the logs into a string
    2. Selects appropriate system prompt from context
    3. Passes logs + role to model
    4. Parses and returns a raw array
    Handles rate-limit/token overage errors gracefully.
    """

    results = []
    
    messages = [
        threat_hunt_system_message,
        threat_hunt_user_message
    ]

    try:
        response = openai_client.chat.completions.create(
            model=openai_model,
            messages=messages,
            response_format={"type": "json_object"}
        )

        results = json.loads(response.choices[0].message.content)
        return results

    except RateLimitError as e:
        error_msg = str(e)

        # Print dark red warning
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}🚨ERROR: Rate limit or token overage detected!{Style.RESET_ALL}")
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}The input was too large for this model or hit rate limits.")
        print(f"{Style.RESET_ALL}——————————\nRaw Error:\n{error_msg}\n——————————")
        print(f"{Fore.WHITE}Suggestions:")
        print(f"- Use fewer logs or reduce input size.")
        print(f"- Switch to a model with a larger context window.")
        print(f"- Retry later if rate-limited.\n")

        return None  # You can also choose to raise again or exit

    except OpenAIError as e:
        print(f"{Fore.RED}Unexpected OpenAI API error:\n{e}")
        return None

# Extract and parse the function call selected by the LLM.
# This tool call is part of OpenAI's function calling feature, where the model chooses a tool (function)
# from the provided list, and returns the arguments it wants to use to call it.
# In this case, the function selected queries log data from Microsoft Defender via Log Analytics.
#
# Docs: https://platform.openai.com/docs/guides/function-calling
def get_log_query_from_agent(openai_client, user_message, model):
    
    print(f"{Fore.LIGHTGREEN_EX}\nDeciding log search parameters based on user request...\n")

    system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_TOOL_SELECTION

    response = openai_client.chat.completions.create(
        model=model,
        messages=[system_message, user_message],
        tools=PROMPT_MANAGEMENT.TOOLS,
        tool_choice="required"
    )

    #TODO: Fix this (if there are no returns)
    function_call = response.choices[0].message.tool_calls[0]
    args = json.loads(function_call.function.arguments)

    return args  # or return function_call, args


def query_log_analytics(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller, user_principal_name):

    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f'''{table_name}
| where FlowType_s == "MaliciousFlow"
| project {fields}'''
        
    elif table_name == "AzureActivity":
        user_query = f'''{table_name}
| where isnotempty(Caller) and Caller !in ("d37a587a-4ef3-464f-a288-445e60ed248c","ef669d55-9245-4118-8ba7-f78e3e7d0212","3e4fe3d2-24ff-4972-92b3-35518d6e6462")
| where Caller startswith "{caller}"
| project {fields}'''
        
    elif table_name == "SigninLogs":
        user_query = f'''{table_name}
| where UserPrincipalName startswith "{user_principal_name}"
| project {fields}'''
        
    else:
        user_query = f'''{table_name}
| where DeviceName startswith "{device_name}"
| project {fields}'''
        
    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{user_query}\n")

    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: '{workspace_id}'...")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=timedelta(hours=timerange_hours)
    )

    if len(response.tables[0].rows) == 0:
        print(f"{Fore.WHITE}No data returned from Log Analytics.")
        return { "records": "", "count": 0 }
    
    # Extract the table
    table = response.tables[0]

    # TODO: Handle if returns 0 events
    record_count = len(response.tables[0].rows)

    # Extract columns and rows using dot notation
    columns = table.columns  # Already a list of strings
    rows = table.rows        # List of row data

    df = pd.DataFrame(rows, columns=columns)
    records = df.to_csv(index=False)

    return { "records": records, "count": record_count }

