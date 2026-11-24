// Owned GFX10.3: jump across a non-instruction word to a two-word VOP2.
.text
fixture_branch:
    v_add_nc_u32_e32 v1, v0, v0
    s_branch write
    .long 0xffffffff
write:
    v_xor_b32_e32 v1, 0xa5a5a5a5, v1
    s_endpgm
