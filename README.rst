REPOSITORY ARCHIVED ON June 2nd, 2020
SUPERSEDED BY:
https://github.com/Parquery/gs-wrap
https://github.com/Parquery/gcloudwrap

gsutilwrap
==========

``gsutilwrap`` wraps Google Storage ``gsutil`` command-line interface in order to simplify the deployment and backup
tasks related to Google Cloud Storage. It provides a set of data manipulation commands including copying, reading,
writing and hashing stored data.

We primarly needed something simple that can still leverage mutli-threading, has decent progress output and implements
robust pattern matching. Since ``gsutil`` CLI already provides all this functionality, we decided to wrap it. The
wrapper adds type-annotated arguments and provides code inspection and autocomplete feature in an IDE such as PyCharm.

Additionally, since ``gsutil`` lacked copying of multiple patterns to multiple targets, we created this extra
feature in ``gsutilwrap``.

If you need to transfer data from/to Google Cloud Storage in the core of your application, we would recommend you to
use the library ``google-cloud-storage`` provided by Google itself. That library is much more sophisticated in terms of
features and would not incur you the overhead of authorizing and spawning a process for each operation. However, it
lacks pattern matching (except for matching the prefixes) and you have to manage multi-threading and progress output
yourself.

Related Projects
================

* https://pypi.org/project/google-cloud-storage/ -- Google own Cloud Storage client

Usage
=====

.. code-block:: python

    import pathlib

    import gsutilwrap

    # list
    lst = gsutilwrap.ls(
        'gs://some-bucket/some-path/**/*.txt')

    lst = gsutilwrap.ls_many(
        ['gs://some-bucket/some-path/**/*.txt',
         'gs://another-bucket/another-path/**/*.xml'],
        multithreaded=True)

    # if you need a listing with size and update time, use long_ls
    entries = gsutilwrap.long_ls(
        'gs://some-bucket/some-path/**/*.txt')

    for entry in entries:
        print("File size and update time of {}: {} {}".format(
            entry.url, entry.size, entry.update_time))

    # write/read text
    gsutilwrap.write_text(
        url='gs://some-bucket/some-path/some-file.txt',
        text='some text')

    text = gsutilwrap.read_text(
        url='gs://some-bucket/some-path/some-file.txt')

    # write/read bytes
    gsutilwrap.write_bytes(
        url='gs://some-bucket/some-path/some-file.bin',
        data=b'x\DE\xAD\xBE\xEF')

    data = gsutilwrap.read_bytes(
        url='gs://some-bucket/some-path/some-file.bin')

    # copy
    gsutilwrap.copy(
        pattern="gs://some-bucket/some-path/*.txt",
        target="/some/dir")

    gsutilwrap.copy_many_to_one(
        patterns=[
            "gs://some-bucket/some-path/*.txt",
            "gs://some-bucket/some-path/*.xml"
        ],
        target="/some/dir")

    gsutilwrap.copy_many_to_many(
        patterns_targets=[
            ("gs://some-bucket/some-path/*.txt", "/some/dir"),
            ("gs://some-bucket/some-path/*.xml", "/some/other/dir")
        ])

    # stat an object
    stat = gsutilwrap.stat(
        url='gs://some-bucket/some-path/some-file.txt')
    print("Modification time: {}".format(stat.file_mtime))
    print("Size: {}".format(stat.content_length))
    print("MD5: {}".format(stat.md5.hex()))


Installation
============

* Create a virtual environment:

.. code-block:: bash

    python3 -m venv venv3

* Activate it:

.. code-block:: bash

    source venv3/bin/activate

* Install ``gsutilwrap`` with pip:

.. code-block:: bash

    pip3 install gsutilwrap

* Make sure you installed ``gsutil`` command-line interface: `gsutil installation`_

.. _`gsutil installation`: https://cloud.google.com/storage/docs/gsutil_install

Development
===========

* Check out the repository.

* In the repository root, create the virtual environment:

.. code-block:: bash

    python3 -m venv venv3

* Activate the virtual environment:

.. code-block:: bash

    source venv3/bin/activate

* Install the development dependencies:

.. code-block:: bash

    pip3 install -e .[dev]

* We provide a set of live tests. The live tests need an existing bucket in the Google Cloud Storage. You need to set
  the URL prefix which will be used for all the live tests *via* the environment variable
  ``TEST_GSUTILWRAP_URL_PREFIX``.

  Mind that the live tests will use Google Cloud resources for which you will be billed. Always check that no resources
  are used after the tests finished so that you don't incur an unnecessary cost!

* We use tox for testing and packaging the distribution. Assuming that the virtual environment has been activated and
  the development dependencies have been installed, run:

.. code-block:: bash

    tox

* We also provide a set of pre-commit checks that lint and check code for formatting. Run them locally from an activated
  virtual environment with development dependencies:

.. code-block:: bash

    ./precommit.py

* The pre-commit script can also automatically format the code:

.. code-block:: bash

    ./precommit.py  --overwrite

Versioning
==========
We follow `Semantic Versioning <http://semver.org/spec/v1.0.0.html>`_. The version X.Y.Z indicates:

* X is the major version (backward-incompatible),
* Y is the minor version (backward-compatible), and
* Z is the patch version (backward-compatible bug fix).
