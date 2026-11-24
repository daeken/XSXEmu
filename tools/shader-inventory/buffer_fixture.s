// Original GFX10.3 compute fixture. Register inputs and descriptor layout are probe-only.
s_load_dwordx4 s[8:11], s[4:5], 0x10
s_waitcnt lgkmcnt(0)
v_xor_b32_e32 v8, 17, v0
buffer_store_dwordx4 v[8:11], v4, s[8:11], 4 offen offset:12
s_endpgm
