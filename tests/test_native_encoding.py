"""Native annotations keep identical wire bytes without per-field heap buffers."""
import unittest

from tests import test_flow_identity as helpers


class NativeEncodingTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def test_annotations_encode_directly_without_heap_scratch(self):
        source = helpers.EXPORT.read_text()
        code = r'''
#include <assert.h>
static unsigned allocations;
static void *counted_realloc(void *p, size_t size) { allocations++; return realloc(p,size); }
#define realloc counted_realloc
'''
        start = source.index("struct proto_buffer {")
        code += source[start:source.index("\n};", start) + 3]
        code += source[source.index("static void proto_free("):source.index("static void native_packet_queue_free(")]
        code += helpers.function(source, "native_annotation_string")
        result = self.run_source(code, r'''
unsigned char storage[512];
struct proto_buffer event={.data=storage,.capacity=sizeof(storage)};
native_annotation_string(&event,"id","abc");
const unsigned char expected[]={0x22,9,0x52,2,'i','d',0x32,3,'a','b','c'};
assert(event.size==sizeof(expected));
assert(!memcmp(event.data,expected,sizeof(expected)));
native_annotation_string(&event,"empty",NULL);
char large[301]; memset(large,'v',300); large[300]=0;
native_annotation_string(&event,"large",large);
assert(!event.failed);
printf("%u",allocations);
''')
        self.assertEqual(result, ["0"])

    def test_numeric_annotations_preserve_decimal_and_hex_text_at_limits(self):
        source = helpers.EXPORT.read_text()
        code = r'''
typedef long long s64;
struct proto_buffer { int unused; };
static void native_annotation_string(struct proto_buffer *e, const char *n, const char *v) {
    (void)e; (void)n; puts(v);
}
''' + "".join(helpers.function(source, name) for name in (
            "native_annotation_uint", "native_annotation_int", "native_annotation_id"))
        result = self.run_source(code, r'''
struct proto_buffer event={};
native_annotation_uint(&event,"n",0);
native_annotation_uint(&event,"n",18446744073709551615ULL);
native_annotation_int(&event,"n",(-9223372036854775807LL-1));
native_annotation_int(&event,"n",9223372036854775807LL);
native_annotation_int(&event,"n",-1);
native_annotation_int(&event,"n",0);
native_annotation_id(&event,"n",0);
native_annotation_id(&event,"n",0x1234abcd5678ef90ULL);
''')
        self.assertEqual(result, ["0", "18446744073709551615", "-9223372036854775808",
                                  "9223372036854775807", "-1", "0", "0000000000000000",
                                  "1234abcd5678ef90"])


if __name__ == "__main__":
    unittest.main()
