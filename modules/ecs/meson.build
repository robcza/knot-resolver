# C module: ecs (EDNS Client Subnet)
# SPDX-License-Identifier: GPL-3.0-or-later

ecs_src = files([
  'ecs.c',
])

c_src_lint += ecs_src

ecs_mod = shared_module(
  'ecs',
  ecs_src,
  dependencies: mod_deps,
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
  link_with: kresd,
)