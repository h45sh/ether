"""Main module entrypoint for python -m ether."""

import sys

from ether.cli.router import main

if __name__ == "__main__":
    sys.exit(main())
