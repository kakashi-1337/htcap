#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTCAP - Web Application Security Scanner for Single Page Applications
Version 2.0.0 - Revival Edition
Author: filippo.cavallarin@wearesegment.com

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

HTCAP is a web application scanner designed to crawl modern Single Page
Applications (SPAs) by intercepting AJAX calls, fetch requests, WebSocket
communications, and DOM changes. It supports GraphQL, REST APIs, and
integrates with various security tools.
"""

import sys
import os
import datetime
import time
import getopt
from typing import List, Optional

from core.lib.utils import get_program_infos, getrealdir
from core.lib.logger import get_logger, set_verbose, set_quiet
from core.crawl.crawler import Crawler
from core.scan.scanner import Scanner
from core.util.util import Util
from core.constants import VERSION, VERSION_NAME


def split_argv(argv: List[str]) -> List[List[str]]:
    """
    Split command line arguments by semicolon delimiter.

    This allows chaining commands like:
    htcap crawl http://example.com db.sqlite \; scan sqlmap \; util report out.html

    Args:
        argv: List of command line arguments

    Returns:
        List of argument lists, one per command
    """
    argvs: List[List[str]] = []
    cur = 0
    for a in argv:
        if a == ";":
            cur += 1
            continue
        if len(argvs) == cur:
            argvs.append([])
        argvs[cur].append(a)
    return argvs


def print_banner() -> None:
    """Print the htcap banner."""
    banner = f"""
╔═══════════════════════════════════════════════════════════════╗
║   HTCAP - Web Application Security Scanner                    ║
║   Version {VERSION} ({VERSION_NAME})                          ║
║   SPA Crawler with GraphQL & Modern API Support               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def usage() -> None:
    """Print usage information."""
    infos = get_program_infos()
    print_banner()
    print(f"""Usage: htcap <command> [options]

Commands are chainable using '\\;' and they share the same database:
  htcap crawl http://example.com db.sqlite \\; scan sqlmap \\; util report out.html

Commands:
  crawl     Crawl a web application and discover endpoints
  scan      Scan discovered endpoints for vulnerabilities
  util      Run utility commands (report, export, etc.)

Global Options:
  -h, --help       Show this help message
  -V, --version    Show version information
  --verbose        Enable verbose output
  --quiet          Suppress non-essential output

Examples:
  # Basic crawl
  htcap crawl https://example.com output.db

  # Crawl with authentication
  htcap crawl -c "session=abc123" https://example.com output.db

  # Crawl and scan for SQL injection
  htcap crawl https://example.com output.db \\; scan sqlmap

  # Generate HTML report
  htcap util report output.db report.html

For detailed help on each command:
  htcap crawl -h
  htcap scan -h
  htcap util -h

Documentation: https://github.com/fcavallarin/htcap
""")


def version() -> None:
    """Print version information."""
    infos = get_program_infos()
    print(f"htcap version {infos['version']}")
    print(f"Author: {infos['author_name']} <{infos['author_email']}>")


def setup_environment(script_path: str) -> None:
    """
    Set up the Node.js environment for the crawler probe.

    Args:
        script_path: Path to the htcap.py script
    """
    node_dir = os.path.join(getrealdir(script_path), 'core', 'nodejs')
    env_sep = ':' if sys.platform != "win32" else ';'
    os.environ["NODE_PATH"] = env_sep.join([
        node_dir,
        os.path.join(node_dir, 'node_modules')
    ])


def main() -> int:
    """
    Main entry point for htcap.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    logger = get_logger('main')

    # Handle global options
    if len(sys.argv) < 2:
        usage()
        return 1

    # Check for global flags
    if sys.argv[1] in ('-h', '--help', 'help'):
        usage()
        return 0
    elif sys.argv[1] in ('-V', '--version', 'version'):
        version()
        return 0
    elif sys.argv[1] == '--verbose':
        set_verbose(True)
        sys.argv.pop(1)
    elif sys.argv[1] == '--quiet':
        set_quiet(True)
        sys.argv.pop(1)

    if len(sys.argv) < 2:
        usage()
        return 1

    # Set up environment
    setup_environment(__file__)

    # Parse commands
    argvs = split_argv(sys.argv[1:])

    # Validate commands
    valid_commands = ('crawl', 'scan', 'util')
    for argv in argvs:
        if not argv:
            continue
        if argv[0] not in valid_commands:
            print(f"Error: Unknown command '{argv[0]}'")
            print(f"Valid commands: {', '.join(valid_commands)}")
            return 1

    # Execute commands
    crawler = None
    scanner = None

    try:
        for argv in argvs:
            if not argv:
                continue

            if argv[0] == "crawl":
                logger.debug("Starting crawler")
                crawler = Crawler(argv[1:])

            elif argv[0] == "scan":
                # Get database file from previous command
                if scanner:
                    dbfile = scanner.db_file
                else:
                    dbfile = crawler.db_file if crawler else None
                logger.debug(f"Starting scanner with database: {dbfile}")
                scanner = Scanner(argv[1:], dbfile)

            elif argv[0] == "util":
                dbfile = crawler.db_file if crawler else (scanner.db_file if scanner else None)
                logger.debug(f"Running utility with database: {dbfile}")
                Util(argv[1:], dbfile)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 130
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
