import os
import json
import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError
from aws_lambda_powertools import Logger

logger = Logger()
bedrock = boto3.client('bedrock-agent')


# pylint: disable=no-value-for-parameter
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, _):

    # get prompt template
    # get datetime
    # format kb entries

    prompt_id = os.environ['BEDROCK_PROMPT_ID']
    prompt_version = os.environ['BEDROCK_PROMPT_VERSION']

    prompt_template: str = get_agent_prompt_template(prompt_id, prompt_version)
    logger.info(
        "Successfully retrieved prompt template", prompt_id=prompt_id, prompt_version=prompt_version
    )

    current_datetime: str = get_current_datetime()
    logger.info("Successfully retrieved current datetime", current_datetime=current_datetime)

    # Extract KB entries from the event
    kb_entries: list[dict] = get_flow_input(event, 'kb_chunks')
    logger.info(f"Successfully extracted {len(kb_entries)} KB entries from input")

    formatted_kb_entries = format_kb_entries(kb_entries)
    logger.info(f"Successfully formatted {len(formatted_kb_entries)} KB entries")

    # Replace placeholders in the prompt template
    final_prompt = prompt_template.replace(r"{{current_datetime}}", current_datetime)
    final_prompt = final_prompt.replace(r"{{sample_queries}}", formatted_kb_entries)
    final_prompt = final_prompt.replace(r"{{user_request}}", get_flow_input(event, 'user_request'))

    logger.info("Successfully formatted final prompt", final_prompt=final_prompt)
    return {
        "current_datetime": current_datetime,
        "final_prompt": final_prompt,
        "prompt_template_info": {
            "prompt_id": prompt_id,
            "prompt_version": prompt_version
        }
    }


def get_agent_prompt_template(prompt_id: str, prompt_version: str) -> str:
    try:
        prompt_variants: list[dict] = bedrock.get_prompt(
            promptIdentifier=prompt_id,
            promptVersion=prompt_version
        )['variants']
    except ClientError as e:
        logger.exception("Failed to get prompt template", prompt_id=prompt_id, prompt_version=prompt_version)
        raise e

    if len(prompt_variants) != 1:
        logger.error(f"Expected 1 prompt variant, got {len(prompt_variants)}", prompt_variants=prompt_variants)
        raise ValueError(f"Expected 1 prompt variant, got {len(prompt_variants)} variants instead ...")

    return prompt_variants[0]['templateConfiguration']['text']['text']


def get_current_datetime() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S %Z")


def format_kb_entries(kb_entries: list[dict]) -> str:

    if not kb_entries:
        logger.info("No KB entries to format")
        return "<no_knowledge_base_entries_found />"

    formatted_entries = []

    for idx, kb_entry in enumerate(kb_entries):
        try:
            # Extract score from KB entry
            score = float(kb_entry['score'])

            # Extract content and metadata from KB chunk
            content = kb_entry['content']['text']
            metadata = kb_entry.get('metadata', {})
            source_uri = metadata.get('x-amz-bedrock-kb-source-uri', 'Unknown source')

            logger.info(f"Processing KB chunk #{idx + 1}", score=score, source=source_uri)

            # Parse the JSON content from text
            try:
                # Strip any leading/trailing whitespace
                content = content.strip()

                # Handle case where content is already in JSON format but as a string
                if content.startswith('{') and content.endswith('}'):
                    # Parse the JSON content
                    parsed_content = json.loads(content)
                else:
                    # If not valid JSON, use as is
                    parsed_content = {"raw_content": content}

            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse content as JSON for entry #{idx + 1}, using raw text", error=str(e))
                parsed_content = {"raw_content": content}

            # Convert confidence score to percentage for better readability
            confidence_percentage = score * 100

            # Format data as XML
            xml_content = f"""<kb_chunk>
  <confidence>{confidence_percentage}%</confidence>"""

            # Add metadata fields
            xml_content += """
  <metadata>"""
            for key, value in metadata.items():
                if key.lower().strip() not in {'service', 'name', 'title', 'category', 'created_at'}:
                    continue
                if value:
                    xml_content += f"""
    <{key}>{value}</{key}>"""
            xml_content += """
  </metadata>"""

            # Add content fields
            xml_content += """
  <content>"""
            if isinstance(parsed_content, dict):
                for key, value in parsed_content.items():
                    if value:
                        xml_content += f"""
    <{key}>{value}</{key}>"""
            xml_content += """
  </content>
</kb_chunk>"""

            formatted_entries.append(xml_content)

        except (KeyError, ValueError) as e:
            logger.warning(f"Error formatting KB entry #{idx + 1}", error=str(e))
            continue

    # Combine all formatted entries with newlines between them
    all_entries = "\n\n".join(formatted_entries)

    if not formatted_entries:
        logger.warning("All KB entries failed to format")
        return "<no_valid_knowledge_base_entries_found />"

    logger.info(f"Successfully formatted {len(formatted_entries)} KB entries")
    return all_entries


# --- HELPER FUNCTIONS ---

def get_flow_input(event: dict, input_name: str) -> Any:
    try:
        return next(
            inp['value'] for inp in event['node']['inputs'] if inp['name'] == input_name
        )
    except (KeyError, TypeError, ValueError, StopIteration) as e:
        logger.exception(f"Failed to extract input {input_name} from event", inputs=event.get('node', {}).get('inputs', []))
        raise e
