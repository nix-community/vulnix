Building vulnix
===============

To create a development environment, use a Python 3 virtualenv::

    python3 -m venv .
    bin/pip install -e ".[test]"

Run tests::

    bin/py.test


Building man pages
==================

The provided makefile needs ronn_ to convert Markdown to troff::

    make -C doc

.. _ronn: https://rtomayko.github.io/ronn/
