// Owned gfx1030 wave32. Host initializes v0, v1 (lane ordinal), v9:v11 and s4:s5.
.text
fixture_exec_store:
    v_cmpx_gt_u32_e32 8, v0
    s_cbranch_execz empty
    v_lshlrev_b32_e32 v4, 4, v1
    s_load_dwordx4 s[8:11], s[4:5], 0x10
    s_waitcnt lgkmcnt(0)
    v_xor_b32_e32 v8, 17, v0
    buffer_store_dwordx4 v[8:11], v4, s[8:11], 4 offen offset:12
    s_endpgm
empty:
    s_endpgm
