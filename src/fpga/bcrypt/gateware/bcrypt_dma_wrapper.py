#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

import os

from migen import *
from litex.gen import *
from litex.soc.interconnect.csr import *
from litex.soc.interconnect import stream

class BcryptDmaWrapper(LiteXModule):
    def __init__(self, platform, num_cores=1, num_cores_dist=0, din_bits=32,
                 feed_group=0, feed_shard=0, collect_group=0, init_batch=0, with_dump=1,
                 with_cmp=1, cslow=1):
        self.sink   = stream.Endpoint([("data", 32)])
        self.source = stream.Endpoint([("data", 8)])

        self._ctrl       = CSRStorage(32)
        self._salt0      = CSRStorage(32)
        self._salt1      = CSRStorage(32)
        self._salt2      = CSRStorage(32)
        self._salt3      = CSRStorage(32)
        self._iter_count = CSRStorage(32)
        self._status     = CSRStatus(32)
        self._core_count = CSRStatus(32, reset=num_cores)

        self._cmp_bm0    = CSRStorage(32)
        self._cmp_bm1    = CSRStorage(32)
        self._cmp_bm2    = CSRStorage(32)
        self._cmp_bm3    = CSRStorage(32)

        self._batch_target = CSRStorage(32)

        self._pad_recs   = CSRStorage(16)

        self._retired    = CSRStatus(32)
        rst = Signal()

        self.comb += rst.eq(ResetSignal("sys") | self._ctrl.storage[0])

        m_last       = Signal()
        frame_status = Signal(32)
        retired_cnt  = Signal(32)

        self.specials += Instance("hcfpga_top",
            p_NUM_CORES      = num_cores,

            p_NUM_CORES_DIST = num_cores_dist,

            p_DIN_BITS       = din_bits,

            p_FEED_GROUP     = feed_group,
            p_FEED_SHARD     = feed_shard,

            p_COLLECT_GROUP  = collect_group,

            p_INIT_BATCH     = init_batch,

            p_WITH_DUMP      = with_dump,

            p_WITH_CMP       = with_cmp,

            p_CSLOW          = cslow,

            i_CLK      = ClockSignal(),
            i_CLK_CORE = ClockSignal("core") if cslow == 2 else ClockSignal("sys"),
            i_rst = rst,

            i_s_data  = self.sink.data,
            i_s_valid = self.sink.valid,
            o_s_ready = self.sink.ready,
            i_s_last  = self.sink.last,

            o_frame_status = frame_status,

            i_salt0      = self._salt0.storage,
            i_salt1      = self._salt1.storage,
            i_salt2      = self._salt2.storage,
            i_salt3      = self._salt3.storage,
            i_iter_count = self._iter_count.storage,
            i_mode_dump  = self._ctrl.storage[1],

            i_cmp_bitmap = Cat(self._cmp_bm0.storage, self._cmp_bm1.storage,
                               self._cmp_bm2.storage, self._cmp_bm3.storage),
            i_cmp_load   = self._cmp_bm3.re,

            i_batch_target = self._batch_target.storage,
            i_batch_arm    = self._batch_target.re,

            i_pad_recs     = self._pad_recs.storage,
            o_retired_cnt  = retired_cnt,

            o_m_data  = self.source.data,
            o_m_valid = self.source.valid,
            i_m_ready = self.source.ready,
            o_m_last  = m_last,
        )

        self.comb += self.source.last.eq(m_last)

        self.comb += self._status.status.eq(frame_status)

        self.comb += self._retired.status.eq(retired_cnt)

    def add_hdl_sources(self):
        from litex.gen import LiteXContext
        here     = os.path.dirname(__file__)
        bcrypt   = os.path.join(here, "bcrypt")
        core_dir = os.path.join(bcrypt, "bcrypt_core")

        LiteXContext.platform.add_verilog_include_path(bcrypt)
        LiteXContext.platform.add_verilog_include_path(core_dir)

        for f in ["bcrypt_core.v", "bcrypt_core_c2.v", "fsm.v", "unit.v", "addr_regs.v", "P_2x32.v", "S.v"]:
            LiteXContext.platform.add_source(os.path.join(core_dir, f))

        for f in ["hcfpga_cores.v", "hcfpga_result_filter.v", "hcfpga_feed.v", "hcfpga_feed_group.v", "hcfpga_collect.v", "hcfpga_collect_group.v", "hcfpga_top.sv"]:
            LiteXContext.platform.add_source(os.path.join(bcrypt, f))
