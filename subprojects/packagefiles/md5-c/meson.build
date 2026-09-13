project('md5-c', 'c')

md5_lib = static_library(
  'md5',
  'md5.c',
  install: false,
)

md5_dep = declare_dependency(
  link_with: md5_lib,
  include_directories: include_directories('.'),
)
