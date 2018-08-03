#!/usr/bin/env python3

# pylint: disable=missing-docstring
# pylint: disable=protected-access

import unittest

import gsutilwrap


class TestGsutilwrap(unittest.TestCase):
    def test_wildcards(self):
        self.assertTrue(gsutilwrap._pattern_contains_no_wildcards(pattern='gs://test-me/indeed012/heyhey_hoi.x'))
        self.assertTrue(gsutilwrap._pattern_contains_no_wildcards(pattern='gs://test-]me['))
        self.assertFalse(gsutilwrap._pattern_contains_no_wildcards(pattern='gs://test-me/indeed012/*'))
        self.assertFalse(gsutilwrap._pattern_contains_no_wildcards(pattern='gs://test-me/**'))
        self.assertFalse(gsutilwrap._pattern_contains_no_wildcards(pattern='gs://test-me?'))
        self.assertFalse(gsutilwrap._pattern_contains_no_wildcards(pattern='gs://test-me[a-z]'))

    def test_group_patterns_by_target(self):
        patterns_targets = [
            ('gs://test-me/*', '/some-target/'),
            ('gs://test-me/xx', '/some-target/xx'),
            ('gs://test-me/*/oioi', '/some-target/'),
            ('gs://test-me/one-file', '/some-target/another-file'),
            ('/test-me/*', 'gs://some-target/'),
            ('/test-me*/*', 'gs://some-target/'),
        ]

        by_target, ungrouped = gsutilwrap._group_patterns_by_target(patterns_targets=patterns_targets)

        expected_by_target = {
            '/some-target/': ['gs://test-me/*', 'gs://test-me/xx', 'gs://test-me/*/oioi'],
            "gs://some-target/": ["/test-me/*", "/test-me*/*"]
        }

        expected_ungrouped = [('gs://test-me/one-file', '/some-target/another-file')]

        self.assertEqual(expected_by_target, by_target)
        self.assertEqual(expected_ungrouped, ungrouped)


if __name__ == '__main__':
    unittest.main()
