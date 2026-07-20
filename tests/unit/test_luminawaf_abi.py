#!/usr/bin/env python3
"""Verify that the Python request adapter mirrors the public C BundleVar ABI."""

import ctypes
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class BundleVar(ctypes.Structure):
    _fields_ = [
        ("ptr", ctypes.POINTER(ctypes.c_ubyte)),
        ("len", ctypes.c_size_t),
        ("var_type", ctypes.c_uint8),
        ("scope", ctypes.c_uint32),
        ("header_mask", ctypes.c_uint32),
        ("collection_mask", ctypes.c_uint64),
        ("name", ctypes.POINTER(ctypes.c_ubyte)),
        ("name_len", ctypes.c_size_t),
    ]


class LuminaBundle(ctypes.Structure):
    _fields_ = [
        ("vars", BundleVar * 16),
        ("count", ctypes.c_int),
        ("hdr_presence_mask", ctypes.c_uint32),
        ("req_method", ctypes.POINTER(ctypes.c_ubyte)),
        ("req_method_len", ctypes.c_size_t),
        ("req_line", ctypes.POINTER(ctypes.c_ubyte)),
        ("req_line_len", ctypes.c_size_t),
        ("user_agent", ctypes.POINTER(ctypes.c_ubyte)),
        ("user_agent_len", ctypes.c_size_t),
        ("req_protocol", ctypes.POINTER(ctypes.c_ubyte)),
        ("req_protocol_len", ctypes.c_size_t),
        ("req_filename", ctypes.POINTER(ctypes.c_ubyte)),
        ("req_filename_len", ctypes.c_size_t),
        ("req_basename", ctypes.POINTER(ctypes.c_ubyte)),
        ("req_basename_len", ctypes.c_size_t),
        ("reqbody_processor", ctypes.POINTER(ctypes.c_ubyte)),
        ("reqbody_processor_len", ctypes.c_size_t),
        ("hdr_host_count", ctypes.c_uint16),
        ("hdr_user_agent_count", ctypes.c_uint16),
        ("hdr_content_type_count", ctypes.c_uint16),
        ("hdr_request_range_count", ctypes.c_uint16),
        ("hdr_transfer_encoding_count", ctypes.c_uint16),
    ]


class BundleVarAbiTest(unittest.TestCase):
    def test_header_presence_mask_has_no_global_request_state(self):
        source = (ROOT / "src" / "luminawaf.cpp").read_text(encoding="utf-8")
        self.assertNotIn("g_hdr_presence_mask_tls", source)

    def test_ctypes_layout_matches_native_header(self):
        source = r'''#include <stddef.h>
#include <stdio.h>
#include "src/luminawaf.h"

int main(void) {
    printf("%zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
           sizeof(BundleVar),
           offsetof(BundleVar, ptr), offsetof(BundleVar, len),
           offsetof(BundleVar, var_type), offsetof(BundleVar, scope),
           offsetof(BundleVar, header_mask),
           offsetof(BundleVar, collection_mask), offsetof(BundleVar, name),
           offsetof(BundleVar, name_len));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            source_path = pathlib.Path(tmp) / "bundle_var_abi.c"
            binary_path = pathlib.Path(tmp) / "bundle_var_abi"
            source_path.write_text(source, encoding="ascii")
            subprocess.run(
                ["cc", "-std=c11", "-I", str(ROOT), str(source_path),
                 "-o", str(binary_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            native = [int(value) for value in subprocess.check_output(
                [str(binary_path)], text=True).split()]

        ctypes_layout = [
            ctypes.sizeof(BundleVar),
            BundleVar.ptr.offset,
            BundleVar.len.offset,
            BundleVar.var_type.offset,
            BundleVar.scope.offset,
            BundleVar.header_mask.offset,
            BundleVar.collection_mask.offset,
            BundleVar.name.offset,
            BundleVar.name_len.offset,
        ]
        self.assertEqual(native, ctypes_layout)

    def test_lumina_bundle_metadata_layout_matches_native_header(self):
        source = r'''#include <stddef.h>
#include <stdio.h>
#include "src/luminawaf.h"

int main(void) {
    printf("%zu %zu %zu %zu %zu %zu %zu %zu\n",
           sizeof(LuminaBundle),
           offsetof(LuminaBundle, count),
           offsetof(LuminaBundle, req_method),
           offsetof(LuminaBundle, req_protocol),
           offsetof(LuminaBundle, req_filename),
           offsetof(LuminaBundle, req_basename),
           offsetof(LuminaBundle, reqbody_processor),
           offsetof(LuminaBundle, hdr_host_count));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            source_path = pathlib.Path(tmp) / "lumina_bundle_abi.c"
            binary_path = pathlib.Path(tmp) / "lumina_bundle_abi"
            source_path.write_text(source, encoding="ascii")
            subprocess.run(
                ["cc", "-std=c11", "-I", str(ROOT), str(source_path),
                 "-o", str(binary_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            native = [int(value) for value in subprocess.check_output(
                [str(binary_path)], text=True).split()]

        ctypes_layout = [
            ctypes.sizeof(LuminaBundle),
            LuminaBundle.count.offset,
            LuminaBundle.req_method.offset,
            LuminaBundle.req_protocol.offset,
            LuminaBundle.req_filename.offset,
            LuminaBundle.req_basename.offset,
            LuminaBundle.reqbody_processor.offset,
            LuminaBundle.hdr_host_count.offset,
        ]
        self.assertEqual(native, ctypes_layout)


if __name__ == "__main__":
    unittest.main()
