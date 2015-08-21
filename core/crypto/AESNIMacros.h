#ifndef AESNIMACROS_H__
#define AESNIMACROS_H__

#define KeyExpansion256(round0,round1) \
    "pshufd $0xff, %%xmm2, %%xmm2 \n" \
    "movaps %%xmm1, %%xmm4 \n" \
    "pslldq $4, %%xmm4 \n" \
    "pxor %%xmm4, %%xmm1 \n" \
    "pslldq $4, %%xmm4 \n" \
    "pxor %%xmm4, %%xmm1 \n" \
    "pslldq $4, %%xmm4 \n" \
    "pxor %%xmm4, %%xmm1 \n" \
    "pxor %%xmm2, %%xmm1 \n" \
    "movaps %%xmm1, "#round0"(%[sched]) \n" \
    "aeskeygenassist $0, %%xmm1, %%xmm4 \n" \
    "pshufd $0xaa, %%xmm4, %%xmm2 \n" \
    "movaps %%xmm3, %%xmm4 \n" \
    "pslldq $4, %%xmm4 \n" \
    "pxor %%xmm4, %%xmm3 \n" \
    "pslldq $4, %%xmm4 \n" \
    "pxor %%xmm4, %%xmm3 \n" \
    "pslldq $4, %%xmm4 \n" \
    "pxor %%xmm4, %%xmm3 \n" \
    "pxor %%xmm2, %%xmm3 \n" \
    "movaps %%xmm3, "#round1"(%[sched]) \n" 

#define EncryptAES256(sched) \
    "pxor (%["#sched"]), %%xmm0 \n" \
    "aesenc 16(%["#sched"]), %%xmm0 \n" \
    "aesenc 32(%["#sched"]), %%xmm0 \n" \
    "aesenc 48(%["#sched"]), %%xmm0 \n" \
    "aesenc 64(%["#sched"]), %%xmm0 \n" \
    "aesenc 80(%["#sched"]), %%xmm0 \n" \
    "aesenc 96(%["#sched"]), %%xmm0 \n" \
    "aesenc 112(%["#sched"]), %%xmm0 \n" \
    "aesenc 128(%["#sched"]), %%xmm0 \n" \
    "aesenc 144(%["#sched"]), %%xmm0 \n" \
    "aesenc 160(%["#sched"]), %%xmm0 \n" \
    "aesenc 176(%["#sched"]), %%xmm0 \n" \
    "aesenc 192(%["#sched"]), %%xmm0 \n" \
    "aesenc 208(%["#sched"]), %%xmm0 \n" \
    "aesenclast 224(%["#sched"]), %%xmm0 \n"

#define DecryptAES256(sched) \
    "pxor 224(%["#sched"]), %%xmm0 \n" \
    "aesdec 208(%["#sched"]), %%xmm0 \n" \
    "aesdec 192(%["#sched"]), %%xmm0 \n" \
    "aesdec 176(%["#sched"]), %%xmm0 \n" \
    "aesdec 160(%["#sched"]), %%xmm0 \n" \
    "aesdec 144(%["#sched"]), %%xmm0 \n" \
    "aesdec 128(%["#sched"]), %%xmm0 \n" \
    "aesdec 112(%["#sched"]), %%xmm0 \n" \
    "aesdec 96(%["#sched"]), %%xmm0 \n" \
    "aesdec 80(%["#sched"]), %%xmm0 \n" \
    "aesdec 64(%["#sched"]), %%xmm0 \n" \
    "aesdec 48(%["#sched"]), %%xmm0 \n" \
    "aesdec 32(%["#sched"]), %%xmm0 \n" \
    "aesdec 16(%["#sched"]), %%xmm0 \n" \
    "aesdeclast (%["#sched"]), %%xmm0 \n"

#define CallAESIMC(offset) \
    "movaps "#offset"(%[shed]), %%xmm0 \n"  \
    "aesimc %%xmm0, %%xmm0 \n" \
    "movaps %%xmm0, "#offset"(%[shed]) \n" 

#endif
