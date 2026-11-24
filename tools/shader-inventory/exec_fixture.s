// Owned gfx1030 wave32: intersect EXEC, branch on empty wave and double survivors.
.text
fixture_exec:
    v_cmpx_gt_u32_e32 8, v0
    s_cbranch_execz empty
    v_add_nc_u32_e32 v1, v0, v0
    s_endpgm
empty:
    s_endpgm
