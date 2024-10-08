from duckdb.sqllogictest.base_statement import BaseStatement
from duckdb.sqllogictest.token import Token


class Halt(BaseStatement):
    def __init__(self, header: Token, line: int):
        super().__init__(header, line)
