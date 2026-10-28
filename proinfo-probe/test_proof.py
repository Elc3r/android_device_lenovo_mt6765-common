#!/usr/bin/env python3
"""Offline byte/CFG checks and bounded Thumb execution of the product worker.

This small interpreter supports only this pinned worker's instructions. Imported
functions are mocks, not execution of Android libraries or a device simulation.
Unknown instructions and imported targets fail closed.
"""
import hashlib
import json
from pathlib import Path
import struct
import unittest

import importlib.util
import sys
spec = importlib.util.spec_from_file_location('migration', Path(__file__).resolve().parent.parent / 'tools/prepare_proinfo_probe_migration.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)
transform, INPUT_SHA256, OFFSET, AFTER = migration.transform, migration.INPUT_SHA256, migration.OFFSET, migration.AFTER

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
VENDOR = ROOT / "vendor/lenovo/mt6765-common/proprietary/vendor"


def run_worker(blob, fd=7, close_ok=True):
    regs = [0] * 16
    regs[13], regs[14] = 0x200000, 0xBADF00D
    memory = {0x71ac: 0x100000, 0x100000: 61}
    calls = []
    pc = OFFSET

    def load(a):
        if a in memory:
            return memory[a]
        if 0 <= a <= len(blob) - 4:
            return struct.unpack_from("<I", blob, a)[0]
        raise AssertionError(f"unexpected memory read {a:x}")

    def imported(target):
        if target == 0x5320:
            calls.append(["log"])
            regs[0] = 0
        elif target == 0x5420:
            lid, read_only = regs[1], load(regs[13])
            calls.append(["get", lid, read_only])
            assert lid == 61 and read_only == 1
            memory[regs[0]] = fd & 0xffffffff
            memory[regs[0] + 4] = lid
            memory[regs[0] + 8] = read_only
            memory[regs[2]], memory[regs[3]] = 1024, 1
        elif target == 0x5440:
            calls.append(["close", *regs[:3]])
            regs[0] = int(close_ok)
        elif target == 0x5480:
            calls.append(["thread_exit", regs[0]])
            return True
        else:
            raise AssertionError(f"unexpected imported target {target:x}")
        return False

    for _ in range(120):
        h = struct.unpack_from("<H", blob, pc)[0]
        nxt = pc + 2
        if h & 0xfe00 == 0xb400:  # push
            rs = [r for r in range(8) if h & (1 << r)]
            if h & 0x100:
                rs.append(14)
            regs[13] -= 4 * len(rs)
            for i, r in enumerate(rs):
                memory[regs[13] + i * 4] = regs[r]
        elif h & 0xff80 == 0xb080:  # sub sp
            regs[13] -= (h & 0x7f) * 4
        elif h & 0xf800 == 0x2000:  # movs immediate
            regs[(h >> 8) & 7] = h & 255
        elif h == 0x4770:  # bx lr
            assert regs[14] == 0xBADF00D
            assert regs[13] == 0x200000
            calls.append(["return", regs[0]])
            return calls, regs
        elif h & 0xf800 == 0x4800:  # ldr literal
            regs[(h >> 8) & 7] = load(((pc + 4) & ~3) + (h & 255) * 4)
        elif h & 0xff00 == 0x4400:  # add high register
            d, s = (h & 7) | ((h >> 4) & 8), (h >> 3) & 15
            regs[d] = (regs[d] + (pc + 4 if s == 15 else regs[s])) & 0xffffffff
        elif h & 0xff00 == 0x4600:  # mov high register
            regs[(h & 7) | ((h >> 4) & 8)] = regs[(h >> 3) & 15]
        elif h & 0xf800 == 0x6800:  # ldr word immediate
            regs[h & 7] = load(regs[(h >> 3) & 7] + ((h >> 6) & 31) * 4)
        elif h & 0xf800 == 0x9000:  # str sp relative
            memory[regs[13] + (h & 255) * 4] = regs[(h >> 8) & 7]
        elif h & 0xf800 == 0xa800:  # add register,sp
            regs[(h >> 8) & 7] = regs[13] + (h & 255) * 4
        elif h & 0xf800 == 0xc800:  # ldm with writeback
            base = (h >> 8) & 7
            rs = [r for r in range(8) if h & (1 << r)]
            a = regs[base]
            for i, r in enumerate(rs):
                regs[r] = load(a + 4 * i)
            if base not in rs:
                regs[base] = a + 4 * len(rs)
        elif h in (0xe9cd, 0xe9dd):  # strd/ldrd sp relative
            h2 = struct.unpack_from("<H", blob, pc + 2)[0]
            a = regs[13] + (h2 & 255) * 4
            r, s = (h2 >> 12) & 15, (h2 >> 8) & 15
            if h == 0xe9cd:
                memory[a], memory[a + 4] = regs[r], regs[s]
            else:
                regs[r], regs[s] = load(a), load(a + 4)
            nxt += 2
        elif h & 0xf800 == 0xf000:  # BLX immediate, ARM interworking target
            h2 = struct.unpack_from("<H", blob, pc + 2)[0]
            assert h2 & 0xd001 == 0xc000
            sign = (h >> 10) & 1
            i1 = 1 ^ ((h2 >> 13) & 1) ^ sign
            i2 = 1 ^ ((h2 >> 11) & 1) ^ sign
            imm = (sign << 24) | (i1 << 23) | (i2 << 22) | ((h & 1023) << 12) | ((h2 & 0x7fe) << 1)
            if sign:
                imm -= 1 << 25
            target = ((pc + 4) & ~3) + imm
            if imported(target):
                return calls, regs
            nxt += 2
        elif h & 0xfd00 == 0xb900:  # CBNZ, forward only
            if regs[h & 7] != 0:
                nxt = pc + 4 + ((h >> 9) & 1) * 64 + ((h >> 3) & 31) * 2
        else:
            raise AssertionError(f"unsupported instruction {h:04x} at {pc:x}")
        pc = nxt
    raise AssertionError("instruction limit exceeded")


class Proof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (VENDOR / "bin/nvram_daemon").read_bytes()
        cls.changed = transform(cls.original)

    def test_input_and_stock_chain(self):
        for row in json.loads((HERE / "binary-provenance.json").read_text()):
            self.assertTrue(row["equal"])
            self.assertEqual(hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest(), row["sha256"])

    def test_exact_reviewed_allocations(self):
        expected = bytearray(self.original)
        expected[0x1f4:0x1f8] = bytes.fromhex('b0b0b080')
        expected[OFFSET:OFFSET + 4] = AFTER
        expected[0x73fe:0x7c6a] = migration.NEW_DEBUG
        self.assertEqual(self.changed, expected)
        self.assertEqual(len(self.changed), len(self.original))
        self.assertEqual(migration.sha(self.changed), migration.OUTPUT_SHA256)
        r1 = self.original[:OFFSET] + AFTER + self.original[OFFSET + 4:]
        self.assertEqual(migration.sha(r1), migration.R1_SHA256)

    def test_reject_unknown_blob(self):
        bad = bytearray(self.original)
        bad[-1] ^= 1
        with self.assertRaises(ValueError):
            transform(bad)

    def test_original_worker_open_close_only(self):
        for fd, close_ok in [(7, True), (-1, False), (7, False)]:
            calls, _ = run_worker(self.original, fd, close_ok)
            self.assertEqual([c for c in calls if c[0] == "get"], [["get", 61, 1]])
            self.assertEqual(len([c for c in calls if c[0] == "close"]), 1)
            self.assertEqual(calls[-1], ["thread_exit", 0])
            self.assertTrue(all(c[0] in {"get", "close", "log", "thread_exit"} for c in calls))

    def test_replacement_returns_null_without_imports(self):
        calls, _ = run_worker(self.changed)
        self.assertEqual(calls, [["return", 0]])

    def test_lid_and_reservation(self):
        b = (VENDOR / "lib/libcustom_nvram.so").read_bytes()
        self.assertEqual(struct.unpack_from("<III", b, 0x9fdc), (61, 0, 0x100000))
        self.assertEqual(struct.unpack_from("<I", b, 0x9fe8)[0], 1)
        self.assertEqual(struct.unpack_from("<I", b, 0xf930)[0], 61)
        self.assertEqual(struct.unpack_from("<II", b, 0x12008 + 1000 + 0x4c), (1024, 1))

    def test_metadata_flags_and_read_branch(self):
        b = (VENDOR / "lib/libnvram.so").read_bytes()
        self.assertEqual(b[0xc302:0xc304], bytes.fromhex("0221"))  # metadata O_RDWR
        self.assertEqual(b[0x12af4:0x12af8], bytes.fromhex("0ea80021"))  # special LID O_RDONLY
        self.assertEqual(b[0x12cd6:0x12ce2], bytes.fromhex("701c1bd030460df030e880b9"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
