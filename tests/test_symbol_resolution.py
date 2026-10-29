"""Resolve cached kallsyms by unique function identity without address guesses."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from tests.test_flow_identity import function

ROOT = Path(__file__).resolve().parents[1]


class SymbolResolutionTests(unittest.TestCase):
    def query(self, fixture, name, *, partial=False, size=256, output=True):
        source = (ROOT / 'utils/parse_sym.c').read_text()
        header = (ROOT / 'utils/parse_sym.h').read_text()
        constants = re.search(r'enum\s*\{[^}]+\};', header).group()
        resolver = function(source, 'sym_search_unique')
        code = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
static char *proc_syms;
static int sym_init_data(void) { return 0; }
''' + constants + resolver + f'''
int main(void) {{
    proc_syms = strdup({json.dumps(fixture)});
    char result[512];
    memset(result, 'X', sizeof(result));
    int status = sym_search_unique({'NULL' if name is None else json.dumps(name)},
                                   {'result' if output else 'NULL'}, {size},
                                   {'true' if partial else 'false'});
    printf("%d\\n", status);
    fwrite(result, 1, sizeof(result), stdout);
    free(proc_syms);
    return 0;
}}
'''
        with tempfile.TemporaryDirectory() as directory:
            cfile, binary = Path(directory) / 'symbols.c', Path(directory) / 'symbols'
            cfile.write_text(code)
            result = subprocess.run(
                ['cc', '-std=gnu11', '-Wall', '-Werror', '-Wno-unused-function',
                 str(cfile), '-o', str(binary)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            result = subprocess.run([str(binary)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        status, buffer = result.stdout.split(b'\n', 1)
        self.assertEqual(len(buffer), 512)
        written_size = size if output else 0
        self.assertEqual(buffer[written_size:], b'X' * (512 - written_size),
                         'resolver wrote beyond the caller-provided buffer')
        return int(status), buffer[:written_size].split(b'\0', 1)[0].decode()

    def test_duplicate_zero_addresses_are_ambiguous(self):
        self.assertEqual(self.query(
            '0000000000000000 t tcp_sendmsg\n'
            '0000000000000000 t tcp_sendmsg [driver]\n', 'tcp_sendmsg'), (3, ''))

    def test_unique_strong_and_weak_functions_are_supported(self):
        for kind in 'TtWw':
            with self.subTest(kind=kind):
                self.assertEqual(self.query(f'00000000\t{kind}\tprobe\n', 'probe'),
                                 (2, 'probe'))

    def test_unique_module_returns_its_complete_function_name(self):
        self.assertEqual(self.query('00000000 t probe.isra.42 [driver]\n',
                                    'probe.', partial=True), (1, 'probe.isra.42'))

    def test_missing_and_substring_names_do_not_match(self):
        fixture = ('00000000 t unrelated\n00000000 t my_probe\n'
                   '00000000 t other [probe]\n')
        for partial in (False, True):
            with self.subTest(partial=partial):
                self.assertEqual(self.query(fixture, 'probe', partial=partial), (0, ''))

    def test_data_only_records_are_not_attachable_functions(self):
        fixture = ''.join(f'00000000 {kind} probe\n' for kind in 'bBdDrRaAnNuU')
        self.assertEqual(self.query(fixture, 'probe'), (0, ''))

    def test_function_and_same_name_data_are_ambiguous_in_either_order(self):
        for records in (['00000000 T probe\n', '00000000 d probe\n'],
                        ['00000000 d probe\n', '00000000 T probe\n']):
            with self.subTest(records=records):
                self.assertEqual(self.query(''.join(records), 'probe'), (3, ''))

    def test_partial_function_and_same_name_data_are_ambiguous(self):
        self.assertEqual(self.query(
            '00000000 r probe.isra.0 [driver]\n00000000 t probe.isra.0\n',
            'probe.', partial=True), (3, ''))

    def test_unrelated_data_suffix_does_not_hide_a_unique_function(self):
        self.assertEqual(self.query(
            '00000000 d probe.constprop.0\n00000000 t probe.isra.0\n',
            'probe.', partial=True), (2, 'probe.isra.0'))

    def test_partial_match_requires_one_candidate(self):
        self.assertEqual(self.query('00000000 t probe.isra.0\n',
                                    'probe.', partial=True), (2, 'probe.isra.0'))
        self.assertEqual(self.query(
            '00000000 t probe.isra.0\n00000000 t probe.constprop.1\n',
            'probe.', partial=True), (3, ''))

    def test_exact_lookup_does_not_count_suffixed_names(self):
        self.assertEqual(self.query(
            '00000000 t probe.isra.0\n00000000 T probe\n', 'probe'), (2, 'probe'))

    def test_duplicate_nonzero_addresses_remain_ambiguous(self):
        self.assertEqual(self.query(
            '00001234 T probe\n00001234 T probe\n', 'probe'), (3, ''))

    def test_buffer_must_fit_the_name_and_terminator(self):
        fixture = '00000000 T probe\n'
        self.assertEqual(self.query(fixture, 'probe', size=5), (0, ''))
        self.assertEqual(self.query(fixture, 'probe', size=6), (2, 'probe'))

    def test_long_records_are_never_truncated_or_ignored_for_ambiguity(self):
        name = 'probe.' + 'x' * 294
        fixture = f'00000000 T {name}\n'
        self.assertEqual(self.query(fixture, name), (0, ''))
        self.assertEqual(self.query(fixture, name, size=301), (2, name))
        self.assertEqual(self.query(fixture + '00000000 t probe.short\n',
                                    'probe.', partial=True), (3, ''))

    def test_malformed_records_do_not_consume_the_next_line(self):
        fixture = ('00000000 T\ninvalid T probe\n00000000 TT probe\n'
                   '00000000 t probe [broken\n00000000 t probe [bad module]\n'
                   '00000000 t probe []\n00000000 T probe unexpected\n'
                   '00000000 T probe')
        self.assertEqual(self.query(fixture, 'probe'), (2, 'probe'))

    def test_empty_query_and_unavailable_output_are_safe(self):
        fixture = '00000000 T probe\n'
        self.assertEqual(self.query(fixture, ''), (0, ''))
        self.assertEqual(self.query(fixture, None), (0, ''))
        self.assertEqual(self.query(fixture, 'probe', size=0), (0, ''))
        self.assertEqual(self.query(fixture, 'probe', output=False), (0, ''))


if __name__ == '__main__':
    unittest.main()
