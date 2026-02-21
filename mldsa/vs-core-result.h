#pragma once

typedef struct result {
     mldsa_lib_error  error;
     tss_buffer buffer;
     Handle     hnd;
     int32_t    finished;
} result;

#define slice_ptr(s) ((s).len > 0 ? &(s) : NULL)
