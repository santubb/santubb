#pragma once

typedef struct {
    unsigned long iplen;        //输入消息长度
    unsigned long state[8];     //A-H8个寄存器
    unsigned char buffer[64];   //存储输入消息的缓冲区
}sm3_context;

void sm3_starts(sm3_context* ctx);//初始化ctx

void sm3_update(sm3_context* ctx, unsigned char* input, int iplen_t);
/*
 * input    缓冲区中的data
 * iplen_t     data长度
 */

void sm3_finish(sm3_context* ctx, unsigned char output[32]);//输出最终结果

void sm3(unsigned char* input, int iplen_t, unsigned char output[32]);
/*
 * input    缓冲区中的data
 * iplen_t     data长度
 * output   最终8个寄存器中的结果
 */#pragma once
