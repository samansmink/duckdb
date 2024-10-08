import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from sqllogictest import SQLLogicPythonRunner


def main():
    script_path = os.path.dirname(os.path.abspath(__file__))
    test_directory = os.path.join(script_path, 'duckdb_unittest_tempdir')
    SQLLogicPythonRunner(test_directory).run()


if __name__ == '__main__':
    main()
