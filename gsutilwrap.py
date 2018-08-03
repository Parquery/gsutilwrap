""" wraps gsutil, a command-line interface to Google Cloud Storage. """

import base64
import concurrent.futures
import contextlib
import datetime
import hashlib
import os
import pathlib
import re
import shlex
import subprocess
import urllib.parse
from typing import List, Tuple, Dict, Optional, Union, cast  # pylint: disable=unused-import


def ls(pattern: str, dont_recurse: bool = False) -> List[str]:  # pylint: disable=invalid-name
    """
    lists the files on Google storage given the pattern.

    Make sure you read how the pattern works since the behavior differs from the Posix "ls" command:
    https://cloud.google.com/storage/docs/gsutil/commands/ls

    :param pattern: URL pattern
    :param dont_recurse: -d option of gsutil ls
    :return: list of URLs according to the given pattern
    """
    cmd = ['gsutil', '-m', 'ls']
    if dont_recurse:
        cmd.append("-d")
    cmd.append(pattern)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = proc.communicate()  # type: Tuple[str, str]

    if err.strip() == 'CommandException: One or more URLs matched no objects.':
        return []

    if proc.returncode == 0:
        return [line.strip() for line in out.split('\n') if line.strip() != '']

    raise RuntimeError("gsutil failed: command was: {}\n, stderr:\n{}".format(" ".join(
        [shlex.quote(part) for part in cmd]), err))


def ls_many(patterns: List[str], dont_recurse: bool = False) -> List[List[str]]:
    """
    lists the files on Google storage given the patterns in parallel threads.

    Make sure you read how the pattern works since the behavior differs from the Posix "ls" command:
    https://cloud.google.com/storage/docs/gsutil/commands/ls

    :param pattern: URL pattern
    :param dont_recurse: bool = False
    :return: list of returned results for each pattern
    """
    result = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []  # type: List[concurrent.futures.Future]
        for pattern in patterns:
            future = executor.submit(ls, pattern=pattern, dont_recurse=dont_recurse)
            futures.append(future)

        for future in futures:
            result.append(future.result())

    return result


class Entry:
    """
    represents entry in a long listing.

    Times are given in UTC. If the URL ends with '/', it represents a directory.
    """

    def __init__(self) -> None:
        self.url = ''
        self.size = None  # type: Optional[int]
        self.update_time = None  # type: Optional[datetime.datetime]


LONG_LS_RE = re.compile(r'^([1-9][0-9]*) +([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z) +(.*)$')


def long_ls(pattern: str, dont_recurse: bool = False) -> List[Entry]:
    """
    performs a long listing of the objects on Google storage given the pattern.

    Make sure you read how the pattern works since the behavior differs from the Posix "ls" command:
    https://cloud.google.com/storage/docs/gsutil/commands/ls

    :param pattern: URL pattern
    :param dont_recurse: -d option of gsutil ls
    :return: listed entries
    """
    cmd = ['gsutil', '-m', 'ls', '-l']
    if dont_recurse:
        cmd.append("-d")
    cmd.append(pattern)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = proc.communicate()  # type: Tuple[str, str]

    if err.strip() == 'CommandException: One or more URLs matched no objects.':
        return []

    if proc.returncode != 0:
        raise RuntimeError("gsutil failed: command was: {}\n, stderr:\n{}".format(" ".join(
            [shlex.quote(part) for part in cmd]), err))

    entries = []  # type: List[Entry]
    for line in out.split('\n'):
        line_stripped = line.strip()
        if line_stripped == '':
            continue

        if line_stripped.startswith('TOTAL'):
            continue

        entry = Entry()
        if line_stripped.endswith('/'):
            # We encountered a directory.
            entry.url = line_stripped
        else:
            mtch = LONG_LS_RE.match(line_stripped)
            if not mtch:
                raise RuntimeError("Unexpected line in the output of gsutil: command: {}\nline:\n{}".format(
                    " ".join([shlex.quote(part) for part in cmd]), line))

            entry.size = int(mtch.group(1))
            entry.update_time = datetime.datetime.strptime(mtch.group(2), '%Y-%m-%dT%H:%M:%SZ')
            entry.url = mtch.group(3)

        entries.append(entry)

    return entries


def copy(pattern: Union[str, pathlib.Path],
         target: Union[str, pathlib.Path],
         quiet: bool = False,
         multithreaded: bool = False,
         recursive: bool = False,
         no_clobber: bool = False,
         preserve_posix: bool = False) -> None:
    # pylint: disable=too-many-arguments
    """
    copies all the sources matching the `pattern` to the target.

    :param pattern: source pattern (URL or a path)
    :param target: target URL or a path
    :param quiet: if set, makes gsutil quiet
    :param multithreaded: use multithreading to copy multiple files simultaneously
    :param recursive:
        (from https://cloud.google.com/storage/docs/gsutil/commands/cp)
        Causes directories, buckets, and bucket subdirectories to be copied recursively. If you neglect to use this
        option for an upload, gsutil will copy any files it finds and skip any directories. Similarly, neglecting to
        specify this option for a download will cause gsutil to copy any objects at the current bucket directory level,
        and skip any subdirectories.
    :param no_clobber:
        (from https://cloud.google.com/storage/docs/gsutil/commands/cp)
        When specified, existing files or objects at the destination will not be overwritten. Any items that are skipped
        by this option will be reported as being skipped. This option will perform an additional GET request to check if
        an item exists before attempting to upload the data. This will save retransmitting data, but the additional HTTP
        requests may make small object transfers slower and more expensive.
    :param preserve_posix:
        (from https://cloud.google.com/storage/docs/gsutil/commands/cp)
        Causes POSIX attributes to be preserved when objects are copied. With this feature enabled, gsutil cp will copy
        fields provided by stat. These are the user ID of the owner, the group ID of the owning group, the mode
        (permissions) of the file, and the access/modification time of the file. For downloads, these attributes will
        only be set if the source objects were uploaded with this flag enabled.

    :return:
    """
    pattern_str = str(pattern)
    target_str = str(target)

    if not target_str.startswith('gs://') and no_clobber:
        raise NotImplementedError(
            "gsutil cp allows no-clobber (-n) only for bucket objects, but not for the target: {!r}".format(target_str))

    cmd = ['gsutil']  # type: List[str]
    if quiet:
        cmd.append('-q')
    if multithreaded:
        cmd.append('-m')
    cmd.append('cp')
    if recursive:
        cmd.append('-r')
    if no_clobber:
        cmd.append('-n')
    if preserve_posix:
        cmd.append('-P')

    cmd.append(pattern_str)
    cmd.append(target_str)

    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, universal_newlines=True)
    _, err = proc.communicate()

    if proc.returncode != 0:
        if err.strip() == "CommandException: No URLs matched: {}".format(pattern):
            raise FileNotFoundError("Copy to {!r} failed since no file matched the pattern: {!r}".format(
                target_str, pattern_str))
        else:
            raise RuntimeError("gsutil failed: command was:\n{}\nstderr:\n{}".format(
                " ".join([shlex.quote(part) for part in cmd]), err))


def copy_many_to_one(patterns: List[Union[str, pathlib.Path]],
                     target: Union[str, pathlib.Path],
                     quiet: bool = False,
                     multithreaded: bool = False,
                     recursive: bool = False,
                     no_clobber: bool = False) -> None:
    # pylint: disable=too-many-arguments
    # pylint: disable=too-many-branches
    """
    copies all the sources matching different patterns to the target.

    :param patterns: source patterns (URLs or paths)
    :param target: target URL or a path
    :param quiet: if set, makes gsutil quiet
    :param multithreaded: use multithreading to copy multiple files simultaneously
    :param recursive:
        (from https://cloud.google.com/storage/docs/gsutil/commands/cp)
        Causes directories, buckets, and bucket subdirectories to be copied recursively. If you neglect to use this
        option for an upload, gsutil will copy any files it finds and skip any directories. Similarly, neglecting to
        specify this option for a download will cause gsutil to copy any objects at the current bucket directory level,
        and skip any subdirectories.
    :param no_clobber:
        (from https://cloud.google.com/storage/docs/gsutil/commands/cp)
        When specified, existing files or objects at the destination will not be overwritten. Any items that are skipped
        by this option will be reported as being skipped. This option will perform an additional GET request to check if
        an item exists before attempting to upload the data. This will save retransmitting data, but the additional HTTP
        requests may make small object transfers slower and more expensive.
    :param preserve_posix:
        (from https://cloud.google.com/storage/docs/gsutil/commands/cp)
        Causes POSIX attributes to be preserved when objects are copied. With this feature enabled, gsutil cp will copy
        fields provided by stat. These are the user ID of the owner, the group ID of the owning group, the mode
        (permissions) of the file, and the access/modification time of the file. For downloads, these attributes will
        only be set if the source objects were uploaded with this flag enabled.

    :return:
    """
    all_strs = True
    for pattern in patterns:
        if not isinstance(pattern, str):
            all_strs = False
            break

    if not all_strs:
        pattern_strs = [str(pattern) for pattern in patterns]
    else:
        pattern_strs = cast(List[str], patterns)

    target_str = str(target)

    if not target_str.startswith('gs://') and no_clobber:
        raise NotImplementedError(
            "gsutil cp allows no-clobber (-n) only for bucket objects, but not for the target: {!r}".format(target_str))

    if target_str.startswith('/'):
        if not os.path.exists(target_str):
            raise FileNotFoundError(
                "To copy many-to-one, the target directory must exist, but it doesn't: {!r}".format(target_str))

        if not os.path.isdir(target_str):
            raise NotADirectoryError("To copy many-to-one, the target must be a directory: {!r}".format(target_str))

    cmd = ['gsutil']  # type: List[str]
    if quiet:
        cmd.append('-q')
    if multithreaded:
        cmd.append('-m')
    cmd.append('cp')
    if recursive:
        cmd.append('-r')
    if no_clobber:
        cmd.append('-n')

    cmd.append('-I')
    cmd.append(target_str)

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    txt = '\n'.join(pattern_strs) + "\n"

    proc.stdin.write(txt)
    _, err = proc.communicate()  # type: Tuple[str, str]

    if proc.returncode != 0:
        if err.strip().startswith("CommandException: No URLs matched:"):
            raise FileNotFoundError("Copy to {!r} failed since no file matched the pattern: {}".format(
                target_str, err.strip()))
        else:
            raise RuntimeError("gsutil failed: command was:\n{}\nstderr:\n{}".format(
                " ".join([shlex.quote(part) for part in cmd]), err))


_WILDCARDS_RE = re.compile(r'(\*|\?|\[[^]]+\])$')


def _pattern_contains_no_wildcards(pattern: str) -> bool:
    """
    :param pattern: used for copying
    :return: True if the pattern contains no wildcards.
    """
    return not _WILDCARDS_RE.search(pattern) is not None


def _group_patterns_by_target(
        patterns_targets: List[Tuple[str, str]]) -> Tuple[Dict[str, List[str]], List[Tuple[str, str]]]:
    """
    groups the patterns by the same target s.t. they can be copied more optimally since we can copy multiple
    patterns to the same target.

    :param patterns_targets: list of (source pattern (URL or path), target URL or path)
    :return: patterns which share the same target, patterns which could not be grouped
    """
    by_target = {}  # type: Dict[str, List[str]]
    ungrouped = []  # type: List[Tuple[str, str]]

    for pattern, target in patterns_targets:
        parsed_pattern = urllib.parse.urlparse(pattern)
        parsed_target = urllib.parse.urlparse(target)

        if parsed_target.path.endswith("/"):
            if target not in by_target:
                by_target[target] = []

            by_target[target].append(pattern)

        elif _pattern_contains_no_wildcards(pattern=pattern):
            pattern_fname = os.path.basename(parsed_pattern.path)
            target_fname = os.path.basename(parsed_target.path)

            if pattern_fname == target_fname:
                target_parent = os.path.dirname(target) + '/'
                if target_parent not in by_target:
                    by_target[target_parent] = []

                by_target[target_parent].append(pattern)
            else:
                ungrouped.append((pattern, target))
        else:
            ungrouped.append((pattern, target))

    return by_target, ungrouped


def copy_many_to_many(patterns_targets: List[Tuple[Union[str, pathlib.Path], Union[str, pathlib.Path]]],
                      quiet: bool = False,
                      multithreaded: bool = False,
                      recursive: bool = False,
                      no_clobber: bool = False) -> None:
    # pylint: disable=too-many-branches
    """
    copies sources matching different patterns to different targets.

    :param patterns_targets: list of (source pattern (URL or path), target URL or path)
    :param quiet: if set, makes gsutil quiet
    :param multithreaded: use multithreading to copy multiple files simultaneously
    :param recursive:
        (from https://cloud.google.com/storage/docs/gsutil/commands/cp)
        Causes directories, buckets, and bucket subdirectories to be copied recursively. If you neglect to use this
        option for an upload, gsutil will copy any files it finds and skip any directories. Similarly, neglecting to
        specify this option for a download will cause gsutil to copy any objects at the current bucket directory level,
        and skip any subdirectories.
    :param no_clobber:
        (from https://cloud.google.com/storage/docs/gsutil/commands/cp)
        When specified, existing files or objects at the destination will not be overwritten. Any items that are skipped
        by this option will be reported as being skipped. This option will perform an additional GET request to check if
        an item exists before attempting to upload the data. This will save retransmitting data, but the additional HTTP
        requests may make small object transfers slower and more expensive.
    :param preserve_posix:
        (from https://cloud.google.com/storage/docs/gsutil/commands/cp)
        Causes POSIX attributes to be preserved when objects are copied. With this feature enabled, gsutil cp will copy
        fields provided by stat. These are the user ID of the owner, the group ID of the owning group, the mode
        (permissions) of the file, and the access/modification time of the file. For downloads, these attributes will
        only be set if the source objects were uploaded with this flag enabled.

    :return:
    """
    # pylint: disable=too-many-locals
    all_strs = True
    for pattern, target in patterns_targets:
        if not isinstance(pattern, str) or not isinstance(target, str):
            all_strs = False
            break

    if not all_strs:
        patterns_targets_strs = [(str(pattern), str(target)) for pattern, target in patterns_targets]
    else:
        patterns_targets_strs = cast(List[Tuple[str, str]], patterns_targets)

    for pattern, target in patterns_targets_strs:
        if not target.startswith('gs://') and no_clobber:
            raise NotImplementedError(
                "gsutil cp allows no-clobber (-n) only for bucket objects, but not for the target: {!r}".format(target))

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []  # type: List[concurrent.futures.Future]

        # optimization: use copy_many_to_one for tuples which share the same prefix and the file name does not change.
        by_target, ungrouped = _group_patterns_by_target(patterns_targets=patterns_targets_strs)

        for target, patterns in by_target.items():
            future = executor.submit(
                copy_many_to_one,
                patterns=patterns,
                target=target,
                quiet=quiet,
                multithreaded=multithreaded,
                recursive=recursive,
                no_clobber=no_clobber)
            futures.append(future)

        for pattern, target in ungrouped:
            future = executor.submit(
                copy,
                pattern=pattern,
                target=target,
                quiet=quiet,
                multithreaded=multithreaded,
                recursive=recursive,
                no_clobber=no_clobber)
            futures.append(future)

        exception_string = ""
        failure_count = 0
        max_printed_failure_count = 10000
        for future in futures:
            # pylint: disable-msg=broad-except
            try:
                future.result()
            except Exception as ex:
                failure_count += 1
                if failure_count < max_printed_failure_count:
                    exception_string += "{}\n".format(ex)

        if failure_count != 0:
            if failure_count >= max_printed_failure_count:
                raise RuntimeError("{} threads copying the files failed. First {} error messages are: {}".format(
                    failure_count, max_printed_failure_count, exception_string))
            else:
                raise RuntimeError("{} threads copying the files failed. The error messages are: {}".format(
                    failure_count, exception_string))


def remove(pattern: str, quiet: bool = False, multithreaded: bool = False, recursive: bool = False) -> None:
    """
    removes files matching the given pattern.

    :param pattern: URL pattern
    :param quiet: if set, makes gsutil quiet
    :param multithreaded: use multithreading to remove multiple files simultaneously
    :param recursive:
        (from https://cloud.google.com/storage/docs/gsutil/commands/rm)
        Causes bucket or bucket subdirectory contents (all objects and subdirectories that it contains) to be removed
        recursively. If used with a bucket-only URL (like gs://bucket), after deleting objects and subdirectories gsutil
        will delete the bucket. This option implies the -a option and will delete all object versions.
    :return:
    """
    cmd = ['gsutil']
    if quiet:
        cmd.append('-q')
    if multithreaded:
        cmd.append('-m')
    cmd.append('rm')
    if recursive:
        cmd.append('-r')
    cmd.append(pattern)
    subprocess.check_call(cmd)


def read_text(url: str, encoding: str = 'utf-8') -> str:
    """
    retrieves the text of the file at the URL. The caller is expected to make sure that the file fits in memory.

    :param url: to the file on the storage
    :param encoding: used to decode the text, defaults to 'utf-8'
    :return: text of the file
    """
    cmd = ['gsutil', 'cat', url]

    return subprocess.check_output(cmd).decode(encoding)


def read_bytes(url: str) -> bytes:
    """
    retrieves the content of the file at the URL. The caller is expected to make sure that the file fits in memory.

    :param url: to the file on the storage
    :return: content of the file
    """
    cmd = ['gsutil', 'cat', url]

    return subprocess.check_output(cmd)


def write_text(url: str, text: str, encoding: str = 'utf-8', quiet: bool = False) -> None:
    """
    writes a text to the storage by the given URL.

    :param url: where to write
    :param text: what to write
    :param encoding: how to encode, defaults to 'utf-8'
    :param quiet: if set, makes gsutil quiet
    :return:
    """
    cmd = ['gsutil']

    if quiet:
        cmd += ['-q']

    cmd += ['cp']

    cmd += ['-', url]

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    proc.communicate(input=text.encode(encoding))

    if proc.returncode != 0:
        raise RuntimeError("Failed to write to the object: {}".format(url))


def write_bytes(url: str, data: bytes, quiet: bool = False) -> None:
    """
    writes bytes to the storage by the given URL.

    :param url: where to write
    :param data: what to write
    :param quiet: if set, makes gsutil quiet
    :return:
    """
    cmd = ['gsutil']

    if quiet:
        cmd += ['-q']

    cmd += ['cp']

    cmd += ['-', url]

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    proc.communicate(input=data)

    if proc.returncode != 0:
        raise RuntimeError("Failed to write to the object: {}".format(url))


class Stat:
    """
    represents stat of an object in Google Storage. Times are given in UTC.
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(self):
        self.creation_time = None  # type: Optional[datetime.datetime]
        self.update_time = None  # type: Optional[datetime.datetime]
        self.storage_class = None  # type: Optional[str]
        self.content_length = None  # type: Optional[int]
        self.file_mtime = None  # type: Optional[datetime.datetime]
        self.file_atime = None  # type: Optional[datetime.datetime]
        self.posix_uid = None  # type: Optional[str]
        self.posix_gid = None  # type: Optional[str]
        self.posix_mode = None  # type: Optional[str]
        self.crc32c = None  # type: Optional[bytes]
        self.md5 = None  # type: Optional[bytes]


def _terminate_or_kill(proc: subprocess.Popen, timeout: Optional[int] = None) -> None:
    """
    terminates the given process. If the process did not terminate after the timeout, kills it.

    :param proc: process to terminate
    :param timeout: in seconds
    :return:
    """
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()


def stat(url: str) -> Optional[Stat]:
    """
    retrieves that stat of the object in the Google Cloud Storage.

    :param url: to the object
    :return: object status, or None if the object does not exist or is a directory.
    """
    # pylint: disable=too-many-branches
    with contextlib.ExitStack() as exit_stack:
        proc = subprocess.Popen(
            ['gsutil', 'stat', url], universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        exit_stack.callback(callback=lambda p=proc: _terminate_or_kill(proc=p, timeout=5))

        stdout, stderr = proc.communicate()

        assert isinstance(stdout, str)
        assert isinstance(stderr, str)

        if stderr.startswith("No URLs matched: {}".format(url)):
            return None

        lines = stdout.split('\n')

        result = Stat()
        valueerr = None  # type: Optional[ValueError]
        try:
            for line in lines:
                fst_colon = line.find(":")
                if fst_colon < 0:
                    continue

                if fst_colon == len(line) - 1:
                    continue

                key = line[:fst_colon].strip()
                value = line[fst_colon + 1:].strip()

                if key == 'Creation time':
                    result.creation_time = datetime.datetime.strptime(value, "%a, %d %b %Y %H:%M:%S GMT")

                elif key == 'Update time':
                    result.update_time = datetime.datetime.strptime(value, "%a, %d %b %Y %H:%M:%S GMT")

                elif key == 'Storage class':
                    result.storage_class = value

                elif key == 'goog-reserved-file-atime':
                    result.file_atime = datetime.datetime.utcfromtimestamp(int(value))

                elif key == 'goog-reserved-file-mtime':
                    result.file_mtime = datetime.datetime.utcfromtimestamp(int(value))

                elif key == 'goog-reserved-posix-uid':
                    result.posix_uid = value

                elif key == 'goog-reserved-posix-gid':
                    result.posix_gid = value

                elif key == 'goog-reserved-posix-mode':
                    result.posix_mode = value

                elif key == "Content-Length":
                    result.content_length = int(value)

                elif key == "Hash (crc32c)":
                    result.crc32c = base64.b64decode(value)

                elif key == "Hash (md5)":
                    result.md5 = base64.b64decode(value)

                else:
                    # ignore the key since we don't know how to handle it.
                    pass

        except ValueError as err:
            valueerr = err

        if valueerr is not None:
            raise ValueError("Failed to parse the stat for {!r}: {}:\n{}".format(url, valueerr, stdout))

        return result


def same_modtime(path: Union[str, pathlib.Path], url: str) -> bool:
    """
    checks if the local path and the URL to an object on Google storage have equal modification times (up to seconds).

    Mind that you need to copy the object with -P (preserve posix) flag.

    :param path: to the local file
    :param url: URL to an object
    :return: True if the modification time is the same
    """
    timestamp = os.stat(str(path)).st_mtime
    dtime = datetime.datetime.utcfromtimestamp(timestamp).replace(microsecond=0)

    url_stat = stat(url=url)

    if url_stat is None:
        raise RuntimeError("The URL does not exist: {}".format(url))

    return dtime == url_stat.update_time


def same_md5(path: Union[str, pathlib.Path], url: str) -> bool:
    """
    checks if the MD5 differs between the local file and the object in Google Storage.

    :param path: to the local file
    :param url:  to the remote object in Google storage
    :return:
        True if the MD5 is the same. False if the checksum differs or local file and/or the remote object do not exist.
    """
    pth_str = str(path)
    if not os.path.exists(pth_str):
        return False

    url_stat = stat(url=url)
    if url_stat is None:
        return False

    hsh = hashlib.md5()
    block_size = 2**20
    with open(pth_str, 'rb') as fid:
        while True:
            buf = fid.read(block_size)
            if not buf:
                break
            hsh.update(buf)

    digest = hsh.digest()

    return url_stat.md5 == digest


def md5_hexdigests(urls: List[str], multithreaded: bool = False) -> List[Optional[str]]:
    """
    retrieves hex digests of MD5 checksums for multiple URLs.

    :param urls: URLs to stat and retrieve MD5 of
    :param multithreaded: if True, uses a thread pool to parallelize
    :return: list of hexdigests; if an URL does not exist, the corresponding item is None.
    """
    hexdigests = []  # type: List[Optional[str]]

    if multithreaded:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            stat_futures = []  # type: List[concurrent.futures.Future]
            for url in urls:
                stat_futures.append(executor.submit(stat, url=url))

            for stat_future in stat_futures:
                sta = stat_future.result()

                hexdigests.append(sta.md5.hex() if sta is not None else None)
    else:
        for url in urls:
            sta = stat(url=url)
            hexdigests.append(sta.md5.hex() if sta is not None else None)

    return hexdigests
