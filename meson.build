project('zzz', 'c',
  version : '0.2.0',
  default_options : [
    'buildtype=release',
    'c_std=gnu23'
  ]
)

if get_option('buildtype') == 'debug'
  add_project_arguments('-Db_sanitize=address', language : 'c')
endif

pcap_dep = dependency('libpcap', required : true)
# event_dep = dependency('libevent', required : true)
inih_dep = dependency('inih', fallback: ['inih', 'inih_dep'] , required : true)
md5_dep = dependency('md5-c', fallback: ['md5-c', 'md5_dep'], required : true)
aes_dep = dependency('tiny-aes-c', fallback: ['tiny-aes-c', 'tint_aes_dep'], required : true)
base64_dep = dependency('base64-c', fallback: ['base64-c', 'base64_dep'], required : true)

inc = include_directories('include', 'src')

src_files = files(
  'src/main.c',
  'src/utils/log.c',
  'src/utils/misc.c',
  'src/utils/config.c',
  'src/interface.c',
  'src/if_impl/pcap.c',
  'src/packet/builder.c',
)

executable('zzz',
  src_files,
  include_directories : inc,
  dependencies : [
    pcap_dep,
    # event_dep,
    inih_dep,
    md5_dep,
    aes_dep,
    base64_dep,
  ],
  install : true
)
