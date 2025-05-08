import time
import datetime

# import boto3
from botocore.exceptions import ClientError
from aws_lambda_powertools import Logger

import sqlparse
from sqlparse.tokens import Keyword, DML, DDL

from .exceptions import (
    AthenaQueryFailedException, AthenaQueryTimedOut, UnsafeAthenaQueryException
)


class Helper:

    def generate_athena_result(
        self, athena, query_string: str, athena_catalog: str, athena_db: str, athena_workgroup: str,
        check_num_rounds=12, round_waittime=5, infer_type=True
    ):
        ''' Generates each row of an athena query ... '''

        def str_is_float(s: str) -> bool:
            try:
                float(s)
                return True
            except ValueError:
                return False

        # start query execution
        try:
            start_query_response = athena.start_query_execution(
                QueryString=query_string,
                QueryExecutionContext={
                    'Catalog': athena_catalog,
                    'Database': athena_db
                },
                WorkGroup=athena_workgroup
            )
            self.logger.info(f"Successfully started athena query with response: \n{start_query_response}")
            query_exec_id = start_query_response['QueryExecutionId']
        except ClientError as e:
            self.logger.error(f"Unable to start athena query of query string {query_string} \nfor database {athena_db} in catalog, with work group: {athena_workgroup} ...")
            raise e

        # check if query finished, and handle non-successful cases
        for num_round in range(1, check_num_rounds + 1):
            try:
                get_query_exec_response = athena.get_query_execution(QueryExecutionId=query_exec_id)
                query_state = get_query_exec_response['QueryExecution']['Status']['State']

                if query_state == 'SUCCEEDED':
                    break
                if query_state in {'QUEUED', 'RUNNING'}:
                    if num_round < check_num_rounds:
                        self.logger.info(f"Found athena query execution to be in state: {query_state}, waiting for {round_waittime} seconds before retrying [{num_round}/{check_num_rounds}] ...")
                        time.sleep(round_waittime)
                    else:
                        raise AthenaQueryTimedOut(f"Athena query execution of ID {query_exec_id} took too long, found query execution to be in state {query_state} even after waiting for {check_num_rounds} rounds of {round_waittime} seconds each ...")
                else:
                    raise AthenaQueryFailedException(f"Athena query execution of ID {query_exec_id} found with state {query_state}, with status details: \n{get_query_exec_response['QueryExecution']['Status']} ...")
            except ClientError as e:
                self.logger.error(f"Unable to get athena query execution of ID {query_exec_id} ...")
                raise e

        results_amount = 0
        header_columns: list[str] = []  # header column of query results
        paginator = athena.get_paginator('get_query_results')

        # yields each data row of query result
        for qe_round, qe_response in enumerate(paginator.paginate(QueryExecutionId=query_exec_id), start=1):
            qe_results = qe_response['ResultSet']['Rows']
            qe_results_amount = len(qe_results)

            results_amount += qe_results_amount
            self.logger.info(f"Get query round {qe_round}: Successfully obtained {qe_results_amount} rows, totalling {results_amount} rows ...")

            for data_row in qe_results:
                data_row: list[dict] = data_row['Data']

                if not header_columns:
                    header_columns = [col['VarCharValue'] for col in data_row]

                else:
                    new_data_row: dict[str, str | int | float | datetime.date] = {}

                    col_data: dict
                    for header_col, col_data in zip(header_columns, data_row):

                        # handle column with empty data
                        col_data = col_data.get('VarCharValue')

                        if infer_type:

                            # if non-negative or negative integer
                            if col_data.isdigit() or (col_data and col_data[0] == '-' and col_data[1:].isdigit()):
                                col_data = int(col_data)

                            # if float (non-integer, as fails the first if)
                            elif str_is_float(col_data):
                                col_data = float(col_data)

                            # if date column
                            elif 'date' in header_col.lower():
                                col_data = datetime.date.fromisoformat(col_data)

                        new_data_row[header_col] = col_data

                    if new_data_row:
                        yield new_data_row

    @staticmethod
    def validate_sql_query(query: str, *, allow_comments: bool = False, allow_multiples: bool = False) -> bool:
        """
        Validates a SQL query for potential SQL injection patterns
        Returns True if query appears safe, False otherwise
        """

        # Parse the SQL query
        parsed = sqlparse.parse(query)
        if not parsed:
            raise AthenaQueryFailedException("Unable to parse query for validation ...")

        # Get the first statement (Athena only executes one at a time anyway)
        stmt = parsed[0]

        # Check for multiple statements (potential SQL injection)
        if not allow_multiples and len(parsed) > 1:
            raise UnsafeAthenaQueryException("Multiple statements found in query, only a single statement is allowed")

        # Check for dangerous keywords that might indicate injection
        dangerous_keywords = {
            'DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE',
            'EXECUTE', 'EXEC', 'UNION', 'INSERT', 'UPDATE'
        }

        # Flatten all tokens and check for dangerous patterns
        tokens = list(stmt.flatten())
        for token in tokens:
            # Check for dangerous keywords
            if token.ttype in (Keyword, DML, DDL) and token.value.upper() in dangerous_keywords:
                raise UnsafeAthenaQueryException(f"Found dangerous keyword: {token.value}")

            # Check for comment markers that might be used to inject
            if not allow_comments and token.value.startswith('--') or token.value.startswith('#') or '/*' in token.value:
                raise UnsafeAthenaQueryException(f"Found comment marker: {token.value}")

        # Check for multiple queries using semicolons - but allow trailing semicolons
        if ';' in query:
            # Split the query by semicolon
            parts = query.split(';')
            # Check if there's any non-whitespace content after the last semicolon
            # Skip the last element as it will always be after a semicolon
            for part in parts[1:-1]:  # Skip last part which may be empty
                if part.strip():
                    raise UnsafeAthenaQueryException("Found multiple queries using semicolon")

            # Check the last part specially (only raise error if there's content after the last semicolon)
            if parts[-1].strip():
                raise UnsafeAthenaQueryException("Found multiple queries using semicolon")

        return True

    def __init__(self, logger: Logger):
        if not isinstance(logger, Logger):
            raise TypeError(f"Logger must be of type {type(Logger)} from Lambda Power Tools ...")
        self.logger = logger
