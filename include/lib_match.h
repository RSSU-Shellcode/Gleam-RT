#ifndef LIB_MATCH_H
#define LIB_MATCH_H

#include "c_types.h"

// MatchByte is used to search the same byte that use brute force.
integer MatchByte(byte* s, integer ns, byte b);

// MatchBytes is used to search the same sub bytes with different strategy.
integer MatchBytes(byte* s, integer ns, byte* sep, integer nsep);

#endif // LIB_MATCH_H
