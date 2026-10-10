// Which commit the firmware was built from.
//
// MW_BUILD_COMMIT comes from src/config/build_commit.h, a one-line header the
// git hooks in .githooks/ write after every commit / checkout (enable them
// once with `git config core.hooksPath .githooks`). It is a short hash such as
// "c50033e", with "-dirty" when the tree had uncommitted changes. A build
// without the file (hooks not enabled, a source archive) says "unknown".
//
// A commit hash, not a build time: the same source still gives the same
// binary, so anyone can rebuild a release and compare (reproducible builds).
#ifndef MW_BUILD_INFO_H
#define MW_BUILD_INFO_H

#if defined(__has_include)
#  if __has_include("build_commit.h")
#    include "build_commit.h"
#  endif
#endif

#ifndef MW_BUILD_COMMIT
#define MW_BUILD_COMMIT "unknown"
#endif

#endif
