#!/usr/bin/env python3

# pylint: disable=missing-docstring

import datetime
import os
import pathlib
import tempfile
import unittest
import uuid
from typing import Optional  # pylint: disable=unused-import

import gsutilwrap

# test environment variable
TEST_GSUTILWRAP_URL_PREFIX = None  # type: Optional[str]


class LiveTestGsutilwrap(unittest.TestCase):
    def test_ls(self) -> None:
        quiet = True

        base_url = "{}/{}".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())

        url_doesnt_exist = "{}/i-dont-exist/really/not-at-all".format(base_url)
        self.assertEqual(0, len(gsutilwrap.ls(pattern=url_doesnt_exist)))

        urls = ['{}/one.txt'.format(base_url), '{}/two.txt'.format(base_url)]
        try:
            for url in urls:
                gsutilwrap.write_text(url=url, text="some dummy content", quiet=quiet)

            for url in urls:
                self.assertEqual(1, len(gsutilwrap.ls(pattern=url)))

            listed_urls = gsutilwrap.ls(pattern='{}/*.txt'.format(base_url))
            self.assertListEqual(urls, listed_urls)

            # Check if dont_recurse is working
            self.assertEqual(2, len(gsutilwrap.ls(pattern="{}/".format(base_url))))
            self.assertEqual(1, len(gsutilwrap.ls(pattern="{}/".format(base_url), dont_recurse=True)))

        finally:
            if len(gsutilwrap.ls(pattern=base_url)) > 0:
                gsutilwrap.remove(pattern=base_url, quiet=True, multithreaded=True, recursive=True)

    def test_many_ls(self) -> None:
        quiet = True

        url_doesnt_exist = "{}/i-dont-exist/really/not-at-all".format(TEST_GSUTILWRAP_URL_PREFIX)
        base_url = "{}/{}".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())

        urls = ['{}/one.txt'.format(base_url), '{}/two.txt'.format(base_url)]
        try:
            for url in urls:
                gsutilwrap.write_text(url=url, text="some dummy content", quiet=quiet)

            patterns = [url_doesnt_exist] + urls
            result = gsutilwrap.ls_many(patterns=patterns)

            self.assertListEqual([[], [base_url + '/one.txt'], [base_url + '/two.txt']], result)

        finally:
            if len(gsutilwrap.ls(pattern=base_url)) > 0:
                gsutilwrap.remove(pattern=base_url, quiet=True, multithreaded=True, recursive=True)

    def test_long_ls(self) -> None:
        quiet = True

        base_url = "{}/{}".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())

        url_doesnt_exist = "{}/i-dont-exist/really/not-at-all".format(base_url)
        self.assertEqual(0, len(gsutilwrap.long_ls(pattern=url_doesnt_exist)))

        urls = ['{}/one.txt'.format(base_url), '{}/two.txt'.format(base_url)]
        try:
            gsutilwrap.write_text(url=urls[0], text="some dummy content", quiet=quiet)
            gsutilwrap.write_text(url=urls[1], text="another dummy content", quiet=quiet)

            for url in urls:
                self.assertEqual(1, len(gsutilwrap.long_ls(pattern=url)))

            entries = gsutilwrap.long_ls(pattern='{}/*.txt'.format(base_url))
            entries.sort(key=lambda entry: entry.url)

            self.assertEqual(urls[0], entries[0].url)
            self.assertEqual(urls[1], entries[1].url)

            self.assertEqual(18, entries[0].size)
            self.assertEqual(21, entries[1].size)

            # Check dont_recurse
            entries = gsutilwrap.long_ls(pattern="{}/".format(base_url), dont_recurse=True)

            self.assertEqual(1, len(entries))
            self.assertTrue(entries[0].url.endswith('/'))
            self.assertIsNone(entries[0].update_time)
            self.assertIsNone(entries[0].size)

        finally:
            if len(gsutilwrap.ls(pattern=base_url)) > 0:
                gsutilwrap.remove(pattern=base_url, quiet=True, multithreaded=True, recursive=True)

    def test_write_read_text(self) -> None:
        quiet = True

        url = "{}/{}/file.txt".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())

        expected_text = 'oi'

        try:
            self.assertEqual(0, len(gsutilwrap.ls(pattern=url)))
            gsutilwrap.write_text(url=url, text=expected_text, quiet=quiet)

            self.assertEqual(1, len(gsutilwrap.ls(pattern=url)))
            text = gsutilwrap.read_text(url=url)

            self.assertEqual(expected_text, text)

        finally:
            if len(gsutilwrap.ls(pattern=url)) > 0:
                gsutilwrap.remove(pattern=url, quiet=True)

    def test_write_read_bytes(self) -> None:
        quiet = True

        url = "{}/{}/file.bin".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())

        expected_data = b'\xDE\xAD\xBE\xEF'

        try:
            self.assertEqual(0, len(gsutilwrap.ls(pattern=url)))

            gsutilwrap.write_bytes(url=url, data=expected_data, quiet=quiet)

            self.assertEqual(1, len(gsutilwrap.ls(pattern=url)))

            data = gsutilwrap.read_bytes(url=url)

            self.assertEqual(expected_data, data)

        finally:
            if len(gsutilwrap.ls(pattern=url)) > 0:
                gsutilwrap.remove(pattern=url, quiet=True)

    def test_copy(self) -> None:
        quiet = True

        base_url = "{}/{}".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())

        with tempfile.TemporaryDirectory() as tmp_dir_name:
            tmp_dir = pathlib.Path(tmp_dir_name)

            try:
                # Create some files in a temporary directory and copy them to the Google Storage
                tmp_file_1 = tmp_dir / "file_1.txt"
                tmp_file_1.write_text('File 1')

                tmp_file_2 = tmp_dir / "file_2.txt"
                tmp_file_2.write_text('File 2')

                # Make sure that nothing is stored in the test_url
                self.assertEqual(0, len(gsutilwrap.ls(pattern=base_url)))

                gsutilwrap.copy(tmp_file_1, "{}/file_0.txt".format(base_url), quiet=quiet)

                self.assertListEqual(['{}/file_0.txt'.format(base_url)], gsutilwrap.ls(base_url))

                gsutilwrap.copy_many_to_one(patterns=[tmp_file_1, tmp_file_2], target=base_url, quiet=quiet)

                self.assertListEqual([
                    '{}/file_0.txt'.format(base_url), '{}/file_1.txt'.format(base_url), '{}/file_2.txt'.format(base_url)
                ], gsutilwrap.ls(base_url))

                gsutilwrap.copy_many_to_many(
                    patterns_targets=[(tmp_file_1, "{}/file_3.txt".format(base_url)),
                                      (tmp_file_2, "{}/file_4.txt".format(base_url))],
                    quiet=quiet)

                self.assertListEqual([
                    '{}/file_0.txt'.format(base_url), '{}/file_1.txt'.format(base_url),
                    '{}/file_2.txt'.format(base_url), '{}/file_3.txt'.format(base_url), '{}/file_4.txt'.format(base_url)
                ], gsutilwrap.ls(base_url))

            finally:
                if len(gsutilwrap.ls(pattern=base_url)) > 0:
                    gsutilwrap.remove(pattern=base_url, quiet=True, multithreaded=True, recursive=True)

    def test_copy_no_clobber(self) -> None:
        quiet = True

        base_url = "{}/{}".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())

        url = '{}/file.txt'.format(base_url)

        with tempfile.TemporaryDirectory() as tmp_dir_name:
            tmp_dir = pathlib.Path(tmp_dir_name)

            try:
                tmp_file = tmp_dir / "file.txt"
                original_content = "original content"
                new_content = "new content"

                tmp_file.write_text(original_content)

                gsutilwrap.copy(pattern=tmp_file, target=url, quiet=quiet)

                content = gsutilwrap.read_text(url=url)
                self.assertEqual(original_content, content)

                # update the file
                tmp_file.write_text(new_content)

                # copy
                gsutilwrap.copy(pattern=tmp_file, target=url, no_clobber=True, quiet=quiet)

                content = gsutilwrap.read_text(url=url)

                self.assertEqual(original_content, content)

                # copy many to one
                gsutilwrap.copy_many_to_one(patterns=[tmp_file], target=base_url + "/", no_clobber=True, quiet=quiet)

                content = gsutilwrap.read_text(url=url)

                self.assertEqual(original_content, content)

                # copy many to many
                gsutilwrap.copy_many_to_many(patterns_targets=[(tmp_file, url)], no_clobber=True, quiet=quiet)

                content = gsutilwrap.read_text(url=url)

                self.assertEqual(original_content, content)

            finally:
                if len(gsutilwrap.ls(pattern=base_url)) > 0:
                    gsutilwrap.remove(pattern=base_url, quiet=True, multithreaded=True, recursive=True)

    def test_stat(self) -> None:
        url = "{}/{}".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())

        with tempfile.TemporaryDirectory() as tmp_dir_name:
            tmp_dir = pathlib.Path(tmp_dir_name)

            pth = tmp_dir / 'testme.txt'
            pth.write_text('tested')

            atime = 1
            mtime = 2
            os.utime(pth.as_posix(), (atime, mtime))

            try:
                gsutilwrap.copy(pattern=pth.as_posix(), target=url, preserve_posix=True, quiet=True)

                stat = gsutilwrap.stat(url=url)
                self.assertIsNotNone(stat)

                # cast
                assert stat is not None

                file_stat = pth.stat()

                self.assertIsNotNone(stat.file_mtime)
                self.assertIsNotNone(stat.content_length)

                # casts
                assert stat.file_mtime is not None
                assert stat.content_length is not None

                self.assertEqual(datetime.datetime.utcfromtimestamp(file_stat.st_mtime), stat.file_mtime)
                self.assertEqual(file_stat.st_size, stat.content_length)

            finally:
                if len(gsutilwrap.ls(pattern=url)) > 0:
                    gsutilwrap.remove(pattern=url, quiet=True, multithreaded=True, recursive=True)

    def test_md5(self) -> None:
        url = "{}/{}".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())
        another_url = "{}/{}".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())
        nonexisting_url = "{}/{}/i-dont-exist/really/not-at-all".format(TEST_GSUTILWRAP_URL_PREFIX, uuid.uuid4())

        with tempfile.TemporaryDirectory() as tmp_dir_name:
            tmp_dir = pathlib.Path(tmp_dir_name)

            pth = tmp_dir / 'testme.txt'
            pth.write_text('tested')

            another_pth = tmp_dir / 'another_testme.txt'
            another_pth.write_text('so different')

            try:
                # same file
                gsutilwrap.copy(pattern=pth, target=url, quiet=True)

                self.assertTrue(
                    gsutilwrap.same_md5(path=pth, url=url), "Expected md5 to be the same, but they were different.")

                # different file
                gsutilwrap.copy(pattern=another_pth.as_posix(), target=url, quiet=True)

                self.assertFalse(
                    gsutilwrap.same_md5(path=pth, url=url), "Expected md5 to be different, but they were same.")

                # non-existing remote object
                self.assertFalse(
                    gsutilwrap.same_md5(path=pth, url=nonexisting_url),
                    "Expected md5 to be different when the object doesn't exist, but they were same.")

                # non-existing local file
                nonexisting_pth = tmp_dir / 'so-does-not-exist.txt'
                self.assertFalse(
                    gsutilwrap.same_md5(path=nonexisting_pth, url=url),
                    "Expected md5 to be different when the local file doesn't exist, but they were same.")

                # check md5 hex digests
                gsutilwrap.copy(pattern=pth, target=url, quiet=True)
                gsutilwrap.copy(pattern=another_pth, target=another_url, quiet=True)

                expected = ['d941191e51e81390343e12b159bb123f', '226c758acdfb13ed5f6e5bea3aef5a4d']

                # multi-threaded
                md5_hexdigests = gsutilwrap.md5_hexdigests(urls=[url, another_url], multithreaded=True)
                self.assertListEqual(expected, md5_hexdigests)

                # single-threaded
                md5_hexdigests = gsutilwrap.md5_hexdigests(urls=[url, another_url])
                self.assertListEqual(expected, md5_hexdigests)

            finally:
                if len(gsutilwrap.ls(pattern=url)) > 0:
                    gsutilwrap.remove(pattern=url, quiet=True, multithreaded=True)

                if len(gsutilwrap.ls(pattern=another_url)) > 0:
                    gsutilwrap.remove(pattern=another_url, quiet=True, multithreaded=True)


if __name__ == '__main__':
    TEST_GSUTILWRAP_URL_PREFIX = os.environ.get('TEST_GSUTILWRAP_URL_PREFIX', None)

    if TEST_GSUTILWRAP_URL_PREFIX is None:
        raise RuntimeError("The environment variable 'TEST_GSUTILWRAP_URL_PREFIX' has not been defined.")

    if not TEST_GSUTILWRAP_URL_PREFIX.startswith("gs://"):
        raise RuntimeError(
            "Expected the environment variable TEST_GSUTILWRAP_URL_PREFIX to be an URL to Google Cloud storage "
            "(starting with 'gs://'), but got: {}".format(TEST_GSUTILWRAP_URL_PREFIX))

    if TEST_GSUTILWRAP_URL_PREFIX.endswith('/'):
        raise RuntimeError("Did not expect the environment variable TEST_GSUTILWRAP_URL_PREFIX "
                           "to end with a slash ('/'), but got: {}".format(TEST_GSUTILWRAP_URL_PREFIX))

    if TEST_GSUTILWRAP_URL_PREFIX == 'gs://':
        raise RuntimeError("Expected at least a bucket name in the environment variable TEST_GSUTILWRAP_URL_PREFIX, "
                           "but got: {}".format(TEST_GSUTILWRAP_URL_PREFIX))

    unittest.main()
