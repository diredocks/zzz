project('base64-c', 'c')

base64_lib = static_library(
  'base64',
  'base64.c',
  install: false,
)

base64_dep = declare_dependency(
  link_with: base64_lib,
  include_directories: include_directories('.')
)
