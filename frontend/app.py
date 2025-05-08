import os
import re
import time
import uuid
import datetime
import hashlib
from typing import Literal

import boto3
import botocore
from botocore.eventstream import EventStream
from botocore.exceptions import BotoCoreError

import streamlit as st
# import streamlit.web.bootstrap as bootstrap

from utils import get_logger, FlowNodeInfo

# Set page config at the very beginning - this must be the first Streamlit command
st.set_page_config(
    page_title="AWS Cost Analysis Chatbot",
    page_icon="💰",
    layout="centered"
)

AWS_REGION = os.environ.get('AWS_REGION', "us-east-1")
FLOW_ID = os.environ['BEDROCK_FLOW_ID']
FLOW_ALIAS_ID = os.environ['BEDROCK_FLOW_ALIAS_ID']
AGENT_ID = os.environ['BEDROCK_AGENT_ID']
AGENT_ALIAS_ID = os.environ['BEDROCK_AGENT_ALIAS_ID']

# Logging configuration
LOG_TO_STDOUT = os.environ.get("LOG_TO_STDOUT", "false").lower() in ("true", "1", "yes")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Password protection configuration
SSM_PASSWORD_PARAM = os.environ.get("SSM_PASSWORD_PARAM")
DEFAULT_PASSWORD = "<DEFAULT_PASSWORD>"  # Fallback password for local development
PASSWORD_HASH = None  # Will be set during initialization


def get_password_from_ssm():
    """Retrieve password from AWS SSM Parameter Store"""

    # First check if we've already retrieved and cached the password in session state
    if 'cached_password' in st.session_state:
        return st.session_state.cached_password

    try:
        # Use the same AWS session as the rest of the application
        if 'aws_session' not in st.session_state:
            aws_profile_name = os.environ.get('AWS_PROFILE', None)
            aws_session = boto3.Session(profile_name=aws_profile_name) if aws_profile_name else boto3.Session()
            st.session_state.aws_session = aws_session
        else:
            aws_session = st.session_state.aws_session

        ssm_client = aws_session.client('ssm', region_name=AWS_REGION)
        response = ssm_client.get_parameter(
            Name=SSM_PASSWORD_PARAM,
            WithDecryption=True  # Important for SecureString parameters
        )
        # Cache the retrieved password in session state
        st.session_state.cached_password = response['Parameter']['Value']
        return st.session_state.cached_password

    except Exception as e:
        # Log the error but don't expose details to UI
        if 'logger' in st.session_state:
            st.session_state.logger.warning(f"Failed to retrieve password from SSM: {str(e)}. Using fallback password.")
        # Cache the fallback password to avoid repeated calls
        st.session_state.cached_password = DEFAULT_PASSWORD
        return DEFAULT_PASSWORD


def initialize_password_hash():
    """Initialize the password hash from SSM or fallback"""
    global PASSWORD_HASH

    # If we've already calculated the hash and stored it in session state, use that
    if 'password_hash' in st.session_state:
        PASSWORD_HASH = st.session_state.password_hash
        return

    # Otherwise calculate the hash and store it in session state
    if PASSWORD_HASH is None:
        password = get_password_from_ssm()
        PASSWORD_HASH = hashlib.sha256(password.encode()).hexdigest()
        st.session_state.password_hash = PASSWORD_HASH


def check_password():
    """Returns True if the user entered the correct password."""

    # Initialize password hash if not already done
    initialize_password_hash()

    if "password_correct" in st.session_state:
        return st.session_state.password_correct

    if "password_attempts" not in st.session_state:
        st.session_state.password_attempts = 0

    # Create a container for the login form
    # This will be cleared after successful login
    login_container = st.container()

    with login_container:
        # Show title and password prompt
        st.title("AWS Cost Analysis Chatbot")
        st.markdown("Please enter the password to access the demo application.")

        # Password input
        password = st.text_input("Password", type="password", key="password_input")

        if st.button("Submit"):
            if hashlib.sha256(password.encode()).hexdigest() == PASSWORD_HASH:
                st.session_state.password_correct = True
                # Use st.rerun() to refresh the page completely, which will clear the login form
                st.rerun()
                return True
            else:
                st.session_state.password_attempts += 1
                st.error(f"Incorrect password. Attempt {st.session_state.password_attempts}/3")

                # Optional: Lock out after too many attempts
                if st.session_state.password_attempts >= 3:
                    st.error("Too many incorrect attempts. Please contact the demo administrator.")
                    st.stop()

                return False
        else:
            # First load without clicking button
            st.stop()  # Halt execution until password is entered

    return False


def main():

    init_session_state()

    # Check password before proceeding
    if not check_password():
        return  # Stop if password check fails or hasn't been completed

    logger = st.session_state.logger
    logger.debug("Session state initialized.")

    # Rest of your application starts here (without set_page_config)
    st.title("AWS Cost Analysis Chatbot")
    st.markdown(
        f"""
        Ask questions about your AWS costs and get insights using Bedrock Flow and Agents.

        Be aware that this is a demo application and may not be fully functional.
        Each request may take a while to process, depending on the complexity of your question, usually 1-2 minutes.
        Please be patient while the system processes your request.

        **Current settings:**
        - AWS Region: {AWS_REGION}
        """
    )

    # Display chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(
                fix_streamlit_message(message["content"])
            )

            # Display processing time if available (for assistant messages only)
            if message["role"] == "assistant" and message.get("processing_time"):
                with st.container():
                    # Create a visually distinct timing information display using Streamlit components
                    st.info(f"Response generated in {message['processing_time']}", icon="⏱️")

            # Display trace information if available
            if (traces := message.get("traces")) is not None:
                with st.expander("Show Flow Execution Steps"):
                    st.markdown(traces.get('flow', "No flow execution steps available."))
                with st.expander("Show Agent Execution Steps"):
                    st.markdown(traces.get('agent', "No agent execution steps available."))

    logger.debug(f"All {len(st.session_state.messages)} messages displayed.")

    if prompt := st.chat_input("Ask about your AWS costs...", disabled=st.session_state.is_processing):

        st.session_state.is_processing = True
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)

        with st.chat_message("assistant"):
            message_placeholder = st.empty()

            # message_placeholder.markdown("Thinking...")
            with st.spinner("Thinking..."):
                progress_placeholder = st.empty()

                request_id = uuid.uuid4()
                logger.append_keys(request_id=request_id)
                logger.info(f"Starting conversation with prompt: {prompt}")

                start_time = time.time()
                formatted_traces: dict[str, str] = {}
                final_message = None

                try:
                    final_message, formatted_traces = process_conversation(logger, message_placeholder, progress_placeholder, prompt)
                    logger.debug(f"Final message: {final_message}")

                except Exception as e:
                    logger.exception(f"Unable to process conversation with prompt: {prompt}")
                    # message_placeholder.markdown(f"Error: Unable to get a response. Please try again later.\n\n**Technical details:** {type(e).__name__}: {str(e)}")
                    write_to_message(
                        message_placeholder,
                        f"Error: Unable to get a response. Please try again later.\n\n**Technical details:** {type(e).__name__}: {str(e)}"
                    )
                    progress_placeholder.empty()

                finally:
                    st.session_state.is_processing = False
                    logger.remove_keys('request_id')

                    # Calculate final time taken
                    total_time_seconds = int(time.time() - start_time)
                    minutes, seconds = divmod(total_time_seconds, 60)
                    time_display = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

                # message_placeholder.markdown(final_message)
                # message_placeholder.write(final_message)
                write_to_message(message_placeholder, final_message)

            st.session_state.messages.append({
                "role": "assistant",
                "content": final_message or "No response received.",
                "traces": formatted_traces,
                "processing_time": time_display
            })
            st.rerun()


def process_conversation(logger, message_placeholder, progress_placeholder, prompt):

    bedrock = st.session_state.bedrock_agent_runtime
    final_message: str
    formatted_traces: dict[str, str] = {}

    logger.append_tags("FLOW")
    try:
        flow_event_type, flow_event_payload, formatted_flow_trace = process_flow(logger, bedrock, message_placeholder, progress_placeholder, prompt)
        logger.info("Successfully proceesed flow ...")

        if formatted_flow_trace:
            formatted_traces['flow'] = formatted_flow_trace

    finally:
        logger.remove_tags("FLOW")
        logger.remove_keys('FLOW_EXEC_ID')

    if flow_event_type == 'output':
        assert isinstance(flow_event_payload, str)
        augmented_prompt: str = flow_event_payload

        logger.append_tags("AGENT")
        agent_session_id = st.session_state.agent_session_id
        logger.append_keys(AGENT_SESSION_ID=agent_session_id)
        try:
            _, agent_event_payload, formatted_agent_trace = process_agent(
                logger, bedrock, message_placeholder, progress_placeholder, augmented_prompt,
                sessionId=agent_session_id
            )
            logger.info("Successfully processed agent ...")

            final_message = agent_event_payload
            if formatted_agent_trace:
                formatted_traces['agent'] = formatted_agent_trace

        finally:
            logger.remove_tags("AGENT")
            logger.remove_keys('AGENT_SESSION_ID')

    else:
        final_message = "Unable to process flow output. Please try again later."

    return final_message, formatted_traces


def process_agent(
    logger, bedrock, message_placeholder, progress_placeholder, prompt, *, sessionId: str, **kwargs
):

    agent_kwargs = {
        "agentAliasId": AGENT_ALIAS_ID,
        "agentId": AGENT_ID,
        "enableTrace": True,
        "inputText": prompt,
        "sessionId": sessionId,
        "streamingConfigurations": {
            "streamFinalResponse": False    # as currently, guardrail may stop the rest of the chunks from being returned if INTERVENED (e.g. MASKED data)
        }
    }
    agent_kwargs.update(kwargs)

    logger.info(f"Starting agent invocation with ID {AGENT_ID} and alias {AGENT_ALIAS_ID} ...")
    logger.debug(f"Starting agent invocation with kwargs: {agent_kwargs}")
    try:
        response = bedrock.invoke_agent(**agent_kwargs)
        logger.debug(f"Successfully obtained agent response: {response}")
    except BotoCoreError as e:
        logger.error(f"Unable to invoke agent with kwargs: {agent_kwargs}")
        raise e
    logger.info(f"Successfully invoked agent with session ID {sessionId} ...")

    # process agent event stream
    agent_traces: list[dict]
    event_type, event_payload, agent_traces = process_agent_event_stream(
        logger, message_placeholder, progress_placeholder, response['completion']
    )

    formatted_agent_trace = format_agent_traces(agent_traces)

    return event_type, event_payload, formatted_agent_trace


AGENT_EXCEPTION_EVENTS = [
    'accessDeniedException', 'badGatewayException', 'conflictException',
    'dependencyFailedException', 'internalServerException', 'modelNotReadyException',
    'resourceNotFoundException', 'serviceQuotaExceededException',
    'throttlingException', 'validationException'
]


def process_agent_event_stream(
    logger, message_placeholder, progress_placeholder, event_stream: EventStream
) -> tuple[Literal['err', 'output'], dict | None, list[dict]]:

    agent_traces: list[dict] = []
    event_type: Literal['err', 'output']
    event_payload = None

    complete_response = ''
    progress_placeholder.markdown("🤖 Agent processing your request...")

    # Track step count for better progress updates
    current_step = 1

    for event in event_stream:
        logger.debug(f"Received agent event: {event}")

        if exception_type := next(
            (_err for _err in FLOW_EXCEPTION_EVENTS if _err in event), None
        ):
            # Error handling code remains unchanged
            exception_event = event[exception_type]
            logger.error(f"Agent {exception_type} error occured: {exception_event}")
            message = exception_event.get('message', f'An error occurred: {exception_type}')

            if 'resourceName' in exception_event:
                resource = exception_event.get('resourceName', 'unknown')
                error_message = f"⚠️ {exception_type} Error with {resource}: {message}"
            elif exception_type == "Internal Server Error" and 'reason' in exception_event:
                reason = exception_event.get('reason', 'unknown')
                error_message = f"⚠️ {exception_type}: {message}. Reason: {reason}"
            else:
                error_message = f"⚠️ {exception_type} Error: {message}"

            # write_to_message(message_placeholder, error_message)
            event_type = 'err'
            event_payload = error_message

            break

        elif 'chunk' in event:
            # Clear progress when we start getting response chunks
            progress_placeholder.markdown("✅ Analysis complete. Formatting response...")

            chunk_data = event['chunk']
            chunk_text: str = chunk_data['bytes'].decode('utf-8')
            logger.debug(f"Received chunk: {chunk_text}")

            complete_response += chunk_text
            write_to_message(message_placeholder, complete_response)

        elif 'trace' in event:
            trace_data = event['trace']['trace']
            trace_types = list(trace_data)

            trace_type = trace_types[0]
            trace_content = trace_data[trace_type]

            # Store all traces for later display
            agent_traces.append({
                'type': trace_type,
                'content': trace_content,
                'event_time': event['trace']['eventTime'],
            })

            # Enhanced progress updates for each trace type
            if trace_type == 'orchestrationTrace':
                # Checking for knowledge base lookups
                if 'invocationInput' in trace_content and 'knowledgeBaseLookupInput' in trace_content['invocationInput']:
                    kb_input = trace_content['invocationInput']['knowledgeBaseLookupInput']
                    kb_id = kb_input.get('knowledgeBaseId', 'unknown')
                    progress_placeholder.markdown(f"🔍 **Step {current_step}:** Searching knowledge base for relevant query patterns...")
                    current_step += 1

                # Checking for action group invocations (SQL queries)
                elif 'invocationInput' in trace_content and 'actionGroupInvocationInput' in trace_content['invocationInput']:
                    action_input = trace_content['invocationInput']['actionGroupInvocationInput']
                    function_name = action_input.get('function', '')

                    if function_name == 'QueryLegacyCUR':
                        progress_placeholder.markdown(f"📊 **Step {current_step}:** Analyzing cost data for anomalies and patterns...")
                        current_step += 1

                # Checking for query results
                elif 'observation' in trace_content:
                    observation = trace_content['observation']

                    if observation.get('type') == 'KNOWLEDGE_BASE':
                        if 'knowledgeBaseLookupOutput' in observation:
                            refs = observation['knowledgeBaseLookupOutput'].get('retrievedReferences', [])
                            progress_placeholder.markdown(f"📚 **Step {current_step}:** Found {len(refs)} relevant document(s) to guide analysis...")
                            current_step += 1

                    elif observation.get('type') == 'ACTION_GROUP':
                        if 'actionGroupInvocationOutput' in observation:
                            output = observation['actionGroupInvocationOutput'].get('text', '')

                            # Display different messages based on whether data was found
                            if '"results": []' in output or '"results":[]' in output:
                                progress_placeholder.markdown(f"ℹ️ **Step {current_step}:** No cost anomalies detected in the analyzed period.")
                            else:
                                progress_placeholder.markdown(f"🔎 **Step {current_step}:** Processing cost anomaly data...")
                            current_step += 1

                    elif observation.get('type') == 'FINISH':
                        progress_placeholder.markdown(f"✍️ **Step {current_step}:** Finalizing analysis and preparing recommendations...")
                        current_step += 1

                # Checking for model invocations
                elif 'modelInvocationInput' in trace_content:
                    progress_placeholder.markdown(f"🧠 **Step {current_step}:** Interpreting data and formulating response...")
                    current_step += 1

                # Checking for rationale
                elif 'rationale' in trace_content:
                    if 'text' in trace_content['rationale']:
                        progress_placeholder.markdown(f"💡 **Step {current_step}:** Developing insights from cost data...")
                        current_step += 1

            # Checking for guardrail evaluations
            elif trace_type == 'guardrailTrace':
                progress_placeholder.markdown(f"🛡️ **Step {current_step}:** Validating compliance of analysis...")

                if trace_content.get('action', 'NONE') == 'INTERVENED':
                    progress_placeholder.markdown(f"⚠️ **Step {current_step}:** Guardrail triggered. Adjusting analysis...")

                    if len(agent_traces) <= 1:
                        logger.warning("No text chunks received when guardrail intevened. Exiting...")
                        event_type = 'err'
                        complete_response = ''
                        event_payload = "No response received - guardrail intervened."
                        break

                current_step += 1

        else:
            raise NotImplementedError(f"Unhandled event type: {event}")

    logger.debug(f"Final complete agent response: {complete_response}")
    if complete_response:
        event_type = 'output'
        event_payload = complete_response
        logger.info("Received complete agent response.")

    return event_type, event_payload, agent_traces


def process_flow(logger, bedrock, message_placeholder, progress_placeholder, prompt):
    flow_kwargs = {
        'flowIdentifier': FLOW_ID,
        'flowAliasIdentifier': FLOW_ALIAS_ID,
        'inputs': [
            {
                'content': {
                    'document': prompt
                },
                'nodeName': 'FlowInputNode',
                'nodeOutputName': 'document'
            }
        ],
        'enableTrace': True
    }

    logger.debug(f"Starting flow invocation with kwargs: {flow_kwargs} ...")
    try:
        response = bedrock.invoke_flow(**flow_kwargs)
        logger.debug(f"Successfully obtained flow response: {response}")
    except BotoCoreError as e:
        logger.error(f"Unable to invoke flow with kwargs: {flow_kwargs}")
        raise e

    flow_execution_id = response['executionId']
    logger.append_keys(FLOW_EXEC_ID=flow_execution_id)
    logger.info("Successfully invoked flow ...")

    # process flow event stream
    event_type, event_payload, node_traces = process_flow_event_stream(
        logger, message_placeholder, progress_placeholder, response['responseStream']
    )
    logger.info(f"Successfully processed flow event stream of type {event_type}, with {len(node_traces)} node traces ...")

    formatted_flow_trace = format_flow_traces(node_traces)

    return event_type, event_payload, formatted_flow_trace


FLOW_EXCEPTION_EVENTS = [
    'accessDeniedException', 'badGatewayException', 'conflictException', 
    'dependencyFailedException', 'internalServerException',
    'resourceNotFoundException', 'serviceQuotaExceededException',
    'throttlingException', 'validationException'
]


def process_flow_event_stream(
    logger, message_placeholder, progress_placeholder, event_stream: EventStream
) -> tuple[Literal['err', 'output'], str, list[FlowNodeInfo]]:

    node_traces: list[FlowNodeInfo] = []
    event_type: Literal['err', 'output']
    event_payload: str

    # Initial progress display
    progress_placeholder.markdown("🔄 Starting flow execution...")

    for event in event_stream:

        # handle exception events
        if exception_type := next(
            (_err for _err in FLOW_EXCEPTION_EVENTS if _err in event), None
        ):

            exception_event = event[exception_type]
            logger.error(f"Flow {exception_type} error occured: {exception_event}")
            message = exception_event.get('message', f'An error occurred: {exception_type}')

            # Add more context to specific error types
            if 'resourceName' in exception_event:
                resource = exception_event.get('resourceName', 'unknown')
                error_message = f"⚠️ {exception_type} Error with {resource}: {message}"
            elif exception_type == "Internal Server Error" and 'reason' in exception_event:
                reason = exception_event.get('reason', 'unknown')
                error_message = f"⚠️ {exception_type}: {message}. Reason: {reason}"
            else:
                error_message = f"⚠️ {exception_type} Error: {message}"

            # message_placeholder.markdown(error_message)
            write_to_message(message_placeholder, error_message)
            event_type = 'err'
            event_payload = error_message

        # Process flow output event
        elif 'flowOutputEvent' in event:
            output_event = event['flowOutputEvent']
            flow_output = output_event['content']['document']
            logger.info(f"Received flow output: {flow_output}")

            progress_placeholder.markdown("✅ Flow processing completed. Preparing agent response...")
            event_type = 'output'
            event_payload = flow_output

        elif 'flowTraceEvent' in event:
            trace = event['flowTraceEvent']['trace']

            trace_name = next(iter(trace.keys()))
            trace_payload = trace[trace_name]
            logger.debug(f"Received flow trace event: {trace_payload} from {trace_name}")

            node_name = trace_payload['nodeName']
            node_timestamp: datetime = trace_payload['timestamp']

            curr_node: FlowNodeInfo
            new_node_trace = not node_traces or (node_name != node_traces[-1].name)
            if new_node_trace:
                curr_node = FlowNodeInfo(
                    name=node_name,
                    start_at=node_timestamp,
                    last_updated_at=node_timestamp
                )
                logger.debug(f"New node trace created: {curr_node}")
                # Show new node execution in progress display
                progress_placeholder.markdown(f"🔄 Processing node: `{node_name}`...")
            else:
                curr_node = node_traces[-1]
                curr_node.last_updated_at = node_timestamp

            if trace_name == 'nodeInputTrace':
                curr_node.node_input = {
                    input_field['nodeInputName']: input_field['content']
                    for input_field in trace_payload['fields']
                }
                logger.debug(f"Updated node input: {curr_node.node_input}")

                # Show details about node input processing
                input_names = list(curr_node.node_input.keys())
                if input_names:
                    progress_placeholder.markdown(f"📥 Node `{node_name}` processing inputs: `{', '.join(input_names)}`")

            elif trace_name == 'nodeOutputTrace':
                curr_node.node_output = {
                    output_field['nodeOutputName']: output_field['content']
                    for output_field in trace_payload['fields']
                }
                logger.debug(f"Updated node output: {curr_node.node_output}")

                # Show details about node output processing
                output_names = list(curr_node.node_output.keys())
                if output_names:
                    progress_placeholder.markdown(f"📤 Node `{node_name}` generated outputs: `{', '.join(output_names)}`")

            elif trace_name == 'nodeActionTrace':
                curr_node.action_info = {k: v for k, v in trace_payload.items() if k not in {'nodeName', 'timestamp'}}
                logger.debug(f"Updated action: {curr_node.action_info}")

                # Show more detailed action information in progress display
                if 'serviceName' in curr_node.action_info and 'operationName' in curr_node.action_info:
                    service = curr_node.action_info['serviceName']
                    operation = curr_node.action_info['operationName']
                    progress_placeholder.markdown(f"🔄 Node `{node_name}` calling `{service}.{operation}`...")

            else:
                logger.warning(f"Ignoring unhandled node trace type: {trace_name}")

            if new_node_trace:
                node_traces.append(curr_node)

        elif 'flowCompletionEvent' in event:
            completion_event = event['flowCompletionEvent']
            completion_reason = completion_event.get('completionReason', 'UNKNOWN')

            if completion_reason == 'SUCCESS':
                progress_placeholder.markdown("✅ Flow Preprocess completed successfully!")
            else:
                progress_placeholder.markdown(f"⚠️ Flow completed with status: {completion_reason}")

            logger.info(f"Flow completed with reason: {completion_reason}")

            break

        else:
            raise NotImplementedError(f"Unhandled event type: {event}")

    return event_type, event_payload, node_traces


def format_flow_traces(node_traces: list[FlowNodeInfo]) -> str:

    if not node_traces:
        return "No flow execution steps available."

    markdown_sections = []

    # Add a header
    # markdown# _sections.append("### Flow Execution Steps")

    for i, node in enumerate(node_traces, 1):
        # Calculate duration
        duration = (node.last_updated_at - node.start_at).total_seconds()
        duration_str = f"{duration:.2f}s" if duration < 60 else f"{int(duration // 60)}m {int(duration % 60)}s"

        # Convert UTC timestamps to Bangkok time (UTC+7)
        bkk_offset = datetime.timedelta(hours=7)
        start_time_bkk = node.start_at + bkk_offset

        # Create node header with timing info
        markdown_sections.append(f"#### {i}. Node: `{node.name}`")
        markdown_sections.append(f"- **Duration**: {duration_str}")
        markdown_sections.append(f"- **Started at**: {start_time_bkk.strftime('%H:%M:%S')} (BKK)")

        # Add action information if available
        if node.action_info:
            markdown_sections.append("- **Action:**")
            if 'serviceName' in node.action_info and 'operationName' in node.action_info:
                markdown_sections.append(f"  - Service: `{node.action_info['serviceName']}`")
                markdown_sections.append(f"  - Operation: `{node.action_info['operationName']}`")

            # Add other action info except timestamp and node name
            for key, value in node.action_info.items():
                if key not in ['serviceName', 'operationName', 'timestamp', 'nodeName']:
                    markdown_sections.append(f"  - {key}: `{value}`")

        # Add input fields if available
        if node.node_input:
            markdown_sections.append("- **Inputs:**")
            for input_name, input_content in node.node_input.items():
                # Format the input content - display as code block
                markdown_sections.append(f"  - `{input_name}`:")
                if isinstance(input_content, str):
                    # If it's a string, treat it as a code snippet
                    markdown_sections.append("    ```")
                    markdown_sections.append(input_content)
                    markdown_sections.append("    ```")
                else:
                    # For non-string content, display as is
                    markdown_sections.append(f"    ```\n    {str(input_content)}\n    ```")

        # Add output fields if available
        if node.node_output:
            markdown_sections.append("- **Outputs:**")
            for output_name, output_content in node.node_output.items():
                # Format the output content - display as code block
                markdown_sections.append(f"  - `{output_name}`:")
                if isinstance(output_content, str):
                    # If it's a string, treat it as a code snippet
                    markdown_sections.append("    ```")
                    markdown_sections.append(output_content)
                    markdown_sections.append("    ```")
                else:
                    # For non-string content, display as is
                    markdown_sections.append(f"    ```\n    {str(output_content)}\n    ```")

        # Add separator between nodes (except after the last one)
        if i < len(node_traces):
            markdown_sections.append("---")

    return "\n".join(markdown_sections)


def format_agent_traces(agent_traces: list[dict]) -> str:

    if not agent_traces:
        return "No agent execution steps available."

    markdown_sections = []

    for i, trace in enumerate(agent_traces, 1):
        trace_type = trace.get('type', 'unknown')
        content = trace.get('content', {})
        event_time = trace.get('event_time')

        # Create trace header with number and type
        markdown_sections.append(f"#### {i}. Step: `{trace_type}`")

        # Add timing information if available
        if event_time:
            # Convert UTC timestamps to Bangkok time (UTC+7)
            bkk_offset = datetime.timedelta(hours=7)
            event_time_bkk = event_time + bkk_offset

            # Calculate duration if previous step exists
            duration_str = ""
            if i > 1 and 'event_time' in agent_traces[i-2]:
                prev_time = agent_traces[i-2]['event_time']
                duration = (event_time - prev_time).total_seconds()
                duration_str = f"- **Duration**: {duration:.2f}s" if duration < 60 else f"- **Duration**: {int(duration // 60)}m {int(duration % 60)}s"
                markdown_sections.append(duration_str)

            markdown_sections.append(f"- **Started at**: {event_time_bkk.strftime('%H:%M:%S')} (BKK)")

        # Add the content as a code block - treat all content as a code snippet
        markdown_sections.append("- **Content:**")
        if isinstance(content, str):
            # If it's a string, treat it as a code snippet
            markdown_sections.append("    ```")
            markdown_sections.append(content)
            markdown_sections.append("    ```")
        else:
            # For non-string content, display as is
            markdown_sections.append(f"    ```\n    {str(content)}\n    ```")

        # Add separator between traces (except after the last one)
        if i < len(agent_traces):
            markdown_sections.append("---")

    return "\n".join(markdown_sections)


def init_session_state():

    if 'logger' not in st.session_state:
        st.session_state.logger = get_logger(log_to_stdout=LOG_TO_STDOUT, log_level=LOG_LEVEL)

    if 'messages' not in st.session_state:
        st.session_state.messages = []

    if 'aws_session' not in st.session_state:

        aws_config = botocore.config.Config(
            read_timeout=180,  # 3 minutes
            connect_timeout=30,  # 30 seconds
            retries={'max_attempts': 3},
            region_name=AWS_REGION
        )
        aws_profile_name = os.environ.get('AWS_PROFILE', None)
        aws_session = boto3.Session(profile_name=aws_profile_name) if aws_profile_name else boto3.Session()

        st.session_state.aws_session = aws_session
        st.session_state.bedrock_agent_runtime = aws_session.client('bedrock-agent-runtime', config=aws_config)

    if 'agent_session_id' not in st.session_state:
        st.session_state.agent_session_id = str(uuid.uuid4())
        st.session_state.logger.info(f"Created new agent session ID: {st.session_state.agent_session_id}")

    if 'is_processing' not in st.session_state:
        st.session_state.is_processing = False


def write_to_message(message_placeholder, text, mode: str = 'md'):
    text = fix_streamlit_message(text)
    if mode == 'md':
        message_placeholder.markdown(text)
    elif mode == 'w':
        message_placeholder.write(text)
    else:
        raise ValueError(f"Unhandled mode: {mode}")


def fix_streamlit_message(text) -> str:
    if not isinstance(text, str) and not text:
        text = "No response received."
    else:
        text = text.replace('$', r'\$')     # a pair of $ encompassing text would be seen as Latex (https://discuss.streamlit.io/t/i-am-having-issues-with-text-display/52305/16)
        text = fix_streamlit_space(text)
    return text


def fix_streamlit_space(text: str) -> str:
    """Fix silly streamlit issue where a newline needs 2 spaces before it.
    See https://github.com/streamlit/streamlit/issues/868

    Credits: https://github.com/streamlit/streamlit/issues/868#issuecomment-2016515781
    """

    def _replacement(match: re.Match):
        # Check if the match is preceded by a space
        if match.group(0).startswith(" "):
            # If preceded by one space, add one more space
            return " \n"
        else:
            # If not preceded by any space, add two spaces
            return "  \n"

    return re.sub(r"( ?)\n", _replacement, text)

if __name__ == "__main__":
    main()
