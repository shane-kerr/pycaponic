import sys

import struct
import tempfile
import unittest

import PcapNGFile


class TestPcapNGFile(unittest.TestCase):
    def setUp(self):
        self.tmp_fp = tempfile.NamedTemporaryFile()

    def tearDown(self):
        self.tmp_fp.close()

    def test_read_pkt_short(self):
        for i in range(12):
            # go to the beginning and write some data (but not enough)
            self.tmp_fp.seek(0)
            self.tmp_fp.write(b'x' * i)
            self.tmp_fp.flush()

            # go back to the beginning and try to read
            self.tmp_fp.seek(0)
            errmsg = "section header block missing header"
            with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
                pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
                pcapng_file.read_pkt()

    def test_read_pkt_bad_type(self):
        # write a bunch of bogus data in our file
        self.tmp_fp.write(b'x' * 256)
        self.tmp_fp.flush()

        # go back to the beginning and try to read
        self.tmp_fp.seek(0)
        errmsg = "section header block bad type"
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

    def test_read_pkt_order_magic(self):
        # write block type
        self.tmp_fp.write(bytes([0x0A, 0x0D, 0x0D, 0x0A]))
        # write total length
        self.tmp_fp.write(bytes([0, 0, 0, 12]))
        # write bogus byte order magic
        self.tmp_fp.write(b'xxxx')
        # write version
        self.tmp_fp.write(b'b' * 12)
        # save and reset our file
        self.tmp_fp.flush()
        self.tmp_fp.seek(0)

        errmsg = "section header block bad byte order magic"
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

    def test_read_pkt_short_header(self):
        # write block type
        self.tmp_fp.write(bytes([0x0A, 0x0D, 0x0D, 0x0A]))
        # write total length (short)
        self.tmp_fp.write(bytes([0, 0, 0, 27]))
        # write byte order magic
        self.tmp_fp.write(bytes([0x1A, 0x2B, 0x3C, 0x4D]))
        # write version
        self.tmp_fp.write(bytes([0x00, 0x01, 0x00, 0x00]))
        # write section length
        self.tmp_fp.write(b'0' * 8)
        # save and reset our file
        self.tmp_fp.flush()
        self.tmp_fp.seek(0)

        errmsg = "section header block too short"
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

    def test_read_pkt_truncated_header(self):
        # write block type
        self.tmp_fp.write(bytes([0x0A, 0x0D, 0x0D, 0x0A]))
        # write total length
        self.tmp_fp.write(bytes([0, 0, 0, 28]))
        # write byte order magic
        self.tmp_fp.write(bytes([0x1A, 0x2B, 0x3C, 0x4D]))
        # write version
        self.tmp_fp.write(bytes([0x00, 0x01, 0x00, 0x00]))
        # write section length
        self.tmp_fp.write(b'\xFF' * 8)
        # save and reset our file
        self.tmp_fp.flush()
        self.tmp_fp.seek(0)

        errmsg = "section header block truncated"
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

    def test_read_pkt_new_version(self):
        new_versions = (bytes([0x00, 0x02, 0x00, 0x00]),
                        bytes([0x00, 0x01, 0x00, 0x01]),
                        bytes([0x00, 0x01, 0x00, 0x99]))
        for version in new_versions:
            self.tmp_fp.seek(0)
            # write block type
            self.tmp_fp.write(bytes([0x0A, 0x0D, 0x0D, 0x0A]))
            # write total length
            self.tmp_fp.write(bytes([0, 0, 0, 28]))
            # write byte order magic
            self.tmp_fp.write(bytes([0x1A, 0x2B, 0x3C, 0x4D]))
            # write version that is not supported
            self.tmp_fp.write(version)
            # write section length
            self.tmp_fp.write(b'\xFF' * 8)
            # write our block length again
            self.tmp_fp.write(bytes([0, 0, 0, 28]))
            # save and reset our file
            self.tmp_fp.flush()
            self.tmp_fp.seek(0)

            errmsg = "Pcap NG format unsupported"
            with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
                pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
                pcapng_file.read_pkt()

    def _make_opt_buf(self, options):
        # make a buffer of our options
        opt_buf = b''
        for opt_code, opt_val in options.items():
            opt_buf += struct.pack('!HH', opt_code, len(opt_val)) + opt_val
            padding = b'\0' * ((4 - (len(opt_val) % 4)) % 4)
            opt_buf += padding
        opt_buf += struct.pack('!HH', PcapNGFile.OPT_ENDOFOPT, 0)
        return opt_buf

    def _write_shb_header(self, opt_buf):
        # write block type
        self.tmp_fp.write(bytes([0x0A, 0x0D, 0x0D, 0x0A]))
        # write total length
        len_buf = struct.pack("!I", 28 + len(opt_buf))
        self.tmp_fp.write(len_buf)
        # write byte order magic
        self.tmp_fp.write(bytes([0x1A, 0x2B, 0x3C, 0x4D]))
        # write version
        self.tmp_fp.write(bytes([0x00, 0x01, 0x00, 0x00]))
        # write section length
        self.tmp_fp.write(b'\xFF' * 8)
        # return the final length block to write
        return len_buf

    def test_read_pkt_bogus_opt(self):
        # create an option section that is very short
        opt_buf = b'x'
        len_buf = self._write_shb_header(opt_buf)
        self.tmp_fp.write(opt_buf)
        self.tmp_fp.write(len_buf)
        self.tmp_fp.flush()
        self.tmp_fp.seek(0)

        errmsg = "option too short"
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

        # reset our file
        self.tmp_fp.seek(0)
        self.tmp_fp.truncate()

        # create an option section that claims to be long but is not
        opt_buf = struct.pack('!HH', PcapNGFile.OPT_COMMENT, 999)
        len_buf = self._write_shb_header(opt_buf)
        self.tmp_fp.write(opt_buf)
        self.tmp_fp.write(len_buf)
        self.tmp_fp.flush()
        self.tmp_fp.seek(0)

        errmsg = "option truncated"
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

        # reset our file
        self.tmp_fp.seek(0)
        self.tmp_fp.truncate()

        # create a file with a duplicated option
        opt_buf = struct.pack("!HH", PcapNGFile.OPT_COMMENT, 0)
        opt_buf *= 2
        len_buf = self._write_shb_header(opt_buf)
        self.tmp_fp.write(opt_buf)
        self.tmp_fp.write(len_buf)
        self.tmp_fp.flush()
        self.tmp_fp.seek(0)

        errmsg = "option %d appears twice in one block" % PcapNGFile.OPT_COMMENT
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

        # reset our file
        self.tmp_fp.seek(0)
        self.tmp_fp.truncate()

        # create a file with a extra data in the options section
        opt_buf = struct.pack("!HH", PcapNGFile.OPT_ENDOFOPT, 0)
        opt_buf += b'xxx'
        len_buf = self._write_shb_header(opt_buf)
        self.tmp_fp.write(opt_buf)
        self.tmp_fp.write(len_buf)
        self.tmp_fp.flush()
        self.tmp_fp.seek(0)

        errmsg = "extra data in option section"
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

        # reset our file
        self.tmp_fp.seek(0)
        self.tmp_fp.truncate()

        # create a file with a extra data in the options section
        opt_buf = struct.pack("!HH", PcapNGFile.OPT_COMMENT, 0)
        len_buf = self._write_shb_header(opt_buf)
        self.tmp_fp.write(opt_buf)
        self.tmp_fp.write(len_buf)
        self.tmp_fp.flush()
        self.tmp_fp.seek(0)

        errmsg = "missing end of option marker"
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

    def test_read_pkt_missing_dup_len(self):
        options = {
            PcapNGFile.OPT_COMMENT: b"this is a gnarly comment",
        }
        opt_buf = self._make_opt_buf(options)
        len_buf = self._write_shb_header(opt_buf)
        self.tmp_fp.write(opt_buf)
        len_buf = bytes([(len_buf[0] + 1) % 256,]) + len_buf[1:]
        self.tmp_fp.write(len_buf)
        self.tmp_fp.flush()
        self.tmp_fp.seek(0)

        errmsg = "section header block length not duplicated"
        with self.assertRaisesRegex(PcapNGFile.PcapNGFileError, errmsg):
            pcapng_file = PcapNGFile.PcapNGFile(self.tmp_fp)
            pcapng_file.read_pkt()

# TODO: confirm works with both byte orders (recognizes them)


if __name__ == '__main__':
    unittest.main()
