project('tiny-aes-c', 'c')

tiny_aes_lib = static_library(
  'tiny-aes',
  'aes.c',
  install: false,
)

tint_aes_dep = declare_dependency(
  link_with: tiny_aes_lib,
  include_directories: include_directories('.'),
)
