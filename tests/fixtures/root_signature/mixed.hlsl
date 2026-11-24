// Original XSXEmu fixture; no shader or title data.
#define ROOT_SIG \
  "RootFlags(ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT | DENY_HULL_SHADER_ROOT_ACCESS)," \
  "DescriptorTable(SRV(t4, numDescriptors=2, space=1, offset=3, flags=DATA_STATIC)," \
  "UAV(u5, numDescriptors=unbounded, space=3, flags=DESCRIPTORS_VOLATILE)," \
  "visibility=SHADER_VISIBILITY_PIXEL)," \
  "RootConstants(num32BitConstants=3, b2, space=7, visibility=SHADER_VISIBILITY_VERTEX)," \
  "CBV(b8, space=4, flags=DATA_VOLATILE)," \
  "SRV(t3, space=9, flags=DATA_STATIC_WHILE_SET_AT_EXECUTE)," \
  "UAV(u6, space=2, flags=DATA_STATIC)," \
  "StaticSampler(s5, space=6, filter=FILTER_COMPARISON_MIN_MAG_MIP_LINEAR," \
  "addressU=TEXTURE_ADDRESS_WRAP, addressV=TEXTURE_ADDRESS_MIRROR, addressW=TEXTURE_ADDRESS_BORDER," \
  "mipLODBias=-0.5, maxAnisotropy=9, comparisonFunc=COMPARISON_GREATER_EQUAL," \
  "borderColor=STATIC_BORDER_COLOR_OPAQUE_WHITE, minLOD=0.25, maxLOD=12.5," \
  "visibility=SHADER_VISIBILITY_PIXEL)"
