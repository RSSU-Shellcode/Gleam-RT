#ifndef LAYOUT_H
#define LAYOUT_H

// +--------------+--------------------+-------------------+
// |    0-4096    |     4096-16384     |    16384-32768    |
// +--------------+--------------------+-------------------+
// | runtime core | runtime submodules | high-level module |
// +--------------+--------------------+-------------------+

#define MAIN_MEM_PAGE_SIZE (8 * 4096)

// runtime core
#define LAYOUT_RUNTIME_STRUCT 1000
#define LAYOUT_RUNTIME_MODULE 2800

// submodule
#define LAYOUT_LT_STRUCT 4096
#define LAYOUT_LT_MODULE 5000

#define LAYOUT_MT_STRUCT 6000
#define LAYOUT_MT_MODULE 7000

// high-level module

#endif // LAYOUT_H
