cargs = ['-DG_LOG_DOMAIN="FuPluginFpc"']
plugins += {meson.current_source_dir().split('/')[-1]: true}

plugin_quirks += join_paths(meson.current_source_dir(), 'fpc.quirk')
plugin_builtins += static_library('fu_plugin_fpc',
  rustgen.process('fu-fpc.rs'),
  sources: [
    'fu-fpc-device.c',
    'fu-fpc-plugin.c',
    'fu-fpc-ff2-firmware.c',
  ],
  include_directories: plugin_incdirs,
  link_with: plugin_libs,
  c_args: cargs,
  dependencies: plugin_deps,
)

device_tests += files(
  'tests/fpc-lenfy-moh.json',
)
