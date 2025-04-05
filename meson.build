mock_lib_sources = [
  'libc_mock.c',
  ]

enable_nl_mock = get_option('enable_nl_mock')

if enable_nl_mock 
  mock_lib_sources += 'nl_mock.c'
endif

include_dir = [
  '../../lib',
  '../../driver'
  ]

wrap_symbols_process = run_command(
  find_program('bash'),
  files('scripts/get_mocks.sh'),
  mock_lib_sources,
  check: false
)


if wrap_symbols_process.returncode() != 0 
  error('Failed to run get_mocks.sh: ' + wrap_symbols_process.stderr())
else
  wrap_link_args = '-Wl,' + wrap_symbols_process.stdout().strip()
  message('wrap_link_args: ' + wrap_link_args)
endif


wrap_symbols_lib = library('wrap_symbols', 
  sources: mock_lib_sources,
  link_depends: mock_lib_sources,
  dependencies: libnl,
  link_args: [wrap_link_args, '-lcmocka'],
  install: false,
)
 
