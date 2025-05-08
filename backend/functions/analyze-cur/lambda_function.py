import os
import json
import tempfile

import boto3
from botocore.exceptions import ClientError

from aws_lambda_powertools import Logger

from helpers import Helper
from helpers.exceptions import (
    AthenaQueryTimedOut, AthenaQueryFailedException, UnsafeAthenaQueryException
)

logger = Logger()
helper = Helper(logger)

athena = boto3.client("athena")

# Maximum allowed size for payload in KB
MAX_PAYLOAD_SIZE_KB = 24


# pylint: disable=no-value-for-parameter
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, _):

    # Extract action_func and parameters from the event dictionary
    action_group = event.get("actionGroup")
    action_func = event.get("function")
    parameters = event.get("parameters", [])
    session_attributes = event.get("sessionAttributes", {})
    prompt_session_attributes = event.get("promptSessionAttributes", {})

    # Convert parameters list to dictionary for easier access
    params = {}
    for param in parameters:
        params[param.get("name")] = param.get("value")

    if action_func == "QueryLegacyCUR":
        json_response = handle_query_legacy_cur(
            params["query_string"],
            os.environ["ATHENA_CATALOG"],
            os.environ["ATHENA_DATABASE"],
            os.environ["ATHENA_WORKGROUP"],
            check_num_rounds=int(os.environ["ATHENA_NUM_ROUNDS"]),
            round_waittime=int(os.environ["ATHENA_WAITTIME"]),
        )
    else:
        raise ValueError(f"Unsupported action function: {action_func}")
    logger.info(f"Successfully handled action function: {action_func} ...")

    response_body = {
        "TEXT": {
            "body": (
                json.dumps(json_response, ensure_ascii=False)
                if not isinstance(json_response, str)
                else json_response
            )
        }
    }

    function_response = {
        "actionGroup": action_group,
        "function": action_func,
        "functionResponse": {"responseBody": response_body},
    }
    logger.info("Returning function response ..", function_response=function_response)

    # Check if payload size is within limits
    try:
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as tmp_file:
            tmp_filepath = tmp_file.name
            json.dump(function_response, tmp_file, ensure_ascii=False)

        # Get file size in KB
        file_size_kb = os.path.getsize(tmp_filepath) / 1024

        # Clean up the temp file
        os.unlink(tmp_filepath)

        if file_size_kb > MAX_PAYLOAD_SIZE_KB:
            logger.warning(f"Payload size {file_size_kb:.2f}KB exceeds maximum allowed size of {MAX_PAYLOAD_SIZE_KB}KB")

            # Create error response instead
            error_message = {
                "error": {
                    "type": "PayloadSizeLimitExceeded",
                    "message": f"Query results too large ({file_size_kb:.2f}KB). Please retry with a more specific query or use LIMIT to reduce the result size.",
                }
            }

            response_body = {
                "TEXT": {
                    "body": json.dumps(error_message, ensure_ascii=False)
                }
            }

            function_response = {
                "actionGroup": action_group,
                "function": action_func,
                "functionResponse": {"responseBody": response_body},
            }

            logger.info("Returning error response due to payload size exceeded", function_response=function_response)

    except Exception as e:
        logger.exception("Error while checking payload size", error=str(e))

    return {
        "messageVersion": "1.0",
        "response": function_response,
        "sessionAttributes": session_attributes,
        "promptSessionAttributes": prompt_session_attributes,
    }


def handle_query_legacy_cur(
    query_string: str,
    athena_catalog: str,
    athena_db: str,
    athena_wg: str,
    *,
    check_num_rounds: int,
    round_waittime: int,
) -> dict:

    logger.append_keys(
        athena_catalog=athena_catalog, athena_db=athena_db, athena_workgroup=athena_wg
    )
    try:
        helper.validate_sql_query(query_string, allow_comments=True)

        results: list[dict] = list(
            helper.generate_athena_result(
                athena,
                query_string,
                athena_catalog,
                athena_db,
                athena_wg,
                check_num_rounds=check_num_rounds,
                round_waittime=round_waittime,
                infer_type=False,  # set to false to ensure json-encodability
            )
        )
        logger.info(f"Successfully obtained {len(results)} rows of query results ...")

        return {
            "message": f"Successfully obtained {len(results)} rows of query results ...",
            "results": results,
        }

    except AthenaQueryTimedOut:
        total_waittime = check_num_rounds * round_waittime
        logger.exception(
            f"Athena query timed out after {check_num_rounds} rounds of {round_waittime} seconds each, totalling {total_waittime * round_waittime} seconds ...",
            query_string=query_string,
        )
        return {
            "error": {
                "type": "AthenaQueryTimedOut",
                "message": f"Query timed out after waiting for total of {total_waittime} seconds, consider retrying with a different, smaller query ...",
            }
        }

    except AthenaQueryFailedException as e:
        logger.exception(
            "Athena query failed to execute ...", query_string=query_string
        )
        return {
            "error": {
                "type": "AthenaQueryFailed",
                "message": "Query failed to execute, investigate the error reason and try to make minimal changes to fix your query, without changing the query semantics ...",
                "reason": str(e),
            }
        }

    except UnsafeAthenaQueryException as e:
        logger.exception(
            "Athena query found to be potentially unsafe ...", query_string=query_string
        )
        return {
            "error": {
                "type": "UnsafeAthenaQuery",
                "message": "Query found to be potentially unsafe, consider retrying with a different query ...",
                "reason": str(e),
            }
        }

    except ClientError as e:
        logger.exception(
            "Unable to execute athena query due to AWS client error ...",
            query_string=query_string,
        )
        return {
            "error": {
                "type": "AWSClientError",
                "message": "Unable to execute query due to AWS client error, investigate the error reason and try again if the error is fixable ...",
                "reason": str(e),
            }
        }

    except Exception as e:
        logger.exception(
            "Unable to execute athena query due to unknown error ...",
            query_string=query_string,
        )
        return {
            "error": {
                "type": "UnknownError",
                "message": "Unable to execute query due to unknown error ...",
                "reason": str(e),
            }
        }

    finally:
        logger.remove_keys(["athena_catalog", "athena_db", "athena_workgroup"])
